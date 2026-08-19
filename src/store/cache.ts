import type { Email, Thread, Mailbox, Identity } from 'jmap-rfc-types'
import type { Card } from '../did/contacts.ts'
import * as idb from './idb.ts'
import * as messages from './messages.ts'
import * as threads from './threads.ts'
import * as mailboxes from './mailboxes.ts'
import * as identities from './identities.ts'
import * as contacts from './contacts.ts'

// Load the browser-local cache into the in-memory stores. Always runs at
// startup (unlike vault/persist.ts's loadFromVault, which only runs once a
// filesystem vault is manually mounted) so the merged inbox has last-sync
// data immediately, and sync/session.ts's querystate-driven delta sync kicks
// in instead of a full historical re-fetch.
export async function loadFromCache(): Promise<void> {
  try {
    const [msgs, thrs, mbx, ids, crds] = await Promise.all([
      idb.getAll(idb.STORES.messages),
      idb.getAll(idb.STORES.threads),
      idb.getAll(idb.STORES.mailboxes),
      idb.getAll(idb.STORES.identities),
      idb.getAll(idb.STORES.contacts),
    ])
    for (const m of msgs) messages.put(m as Email)
    for (const t of thrs) threads.put(t as Thread)
    if (mbx.length) mailboxes.set(mbx[0] as Mailbox[])
    if (ids.length) identities.loadStamped(ids[0] as (Identity & { _account?: string })[])
    if (crds.length) contacts.set(crds[0] as Card[])
  } catch (e) { console.warn('[cache] loadFromCache failed', e) }
}

export async function putMessage(email: Email): Promise<void> {
  try { await idb.put(idb.STORES.messages, email) } catch { /* best-effort */ }
}

export async function deleteMessage(account: string, id: string): Promise<void> {
  try { await idb.del(idb.STORES.messages, [account, id]) } catch { /* best-effort */ }
}

export async function putThread(thread: Thread): Promise<void> {
  try { await idb.put(idb.STORES.threads, thread) } catch { /* best-effort */ }
}

export async function putMailboxes(list: Mailbox[]): Promise<void> {
  try { await idb.put(idb.STORES.mailboxes, list, 'all') } catch { /* best-effort */ }
}

export async function putIdentities(list: Identity[]): Promise<void> {
  try { await idb.put(idb.STORES.identities, list, 'all') } catch { /* best-effort */ }
}

export async function putContacts(list: Card[]): Promise<void> {
  try { await idb.put(idb.STORES.contacts, list, 'all') } catch { /* best-effort */ }
}

// Purge one identity's cached messages + threads + sync cursors across all
// its relays (mail + AP) — called from per-account "Log out" so a removed
// identity's data can't resurrect from cache if it (or another identity in
// the same browser) reconnects later. Must run BEFORE the caller drops the
// identity's session(s) from `sessions[]` — `messages.forIdentity` resolves
// via `relaysForId`, a lookup against the currently LIVE sessions, so
// calling this after they're gone silently matches nothing (found live,
// 2026-08-19 — left-pane.ts's removeRelayLocally's own note has the story).
//
// Clears BOTH the persisted IDB rows and the in-memory stores — this is a
// long-lived SPA page, not a reload, so a delete-then-immediate-reclaim of
// the SAME identity (SCID-primary reuses the identical account key —
// PLANSCID.md) would otherwise keep serving the old in-memory messages/
// threads for the rest of this page's lifetime even with IDB itself clean.
export async function clearIdentity(identity: string): Promise<void> {
  const msgs = messages.forIdentity(identity)
  const accts = new Set(msgs.map(e => messages.accountOf(e)))
  // Collected before the loop below removes the messages that name them —
  // a thread with no messages left pointing at it is exactly the stale
  // "hi" / "Encrypted message" ghost this was missing (threads.ts's own
  // note on why messages/threads must be purged together).
  const threadIds = new Set(msgs.map(e => e.threadId).filter((id): id is string => !!id))
  for (const e of msgs) messages.remove(messages.accountOf(e), e.id as string)
  for (const id of threadIds) {
    threads.remove(id)
    try { await idb.del(idb.STORES.threads, id) } catch { /* best-effort */ }
  }
  for (const acct of accts) {
    if (!acct) continue
    try { await idb.delRange(idb.STORES.messages, IDBKeyRange.bound([acct, ''], [acct, '￿'])) } catch { /* best-effort */ }
    try { await idb.del(idb.STORES.querystate, acct) } catch { /* best-effort */ }
  }
}

// Full wipe — called from logout().
export function clearAll(): Promise<void> {
  return idb.deleteDB()
}
