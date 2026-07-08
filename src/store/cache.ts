import type { Email, Thread, Mailbox, Identity } from 'jmap-rfc-types'
import * as idb from './idb.ts'
import * as messages from './messages.ts'
import * as threads from './threads.ts'
import * as mailboxes from './mailboxes.ts'
import * as identities from './identities.ts'

// Load the browser-local cache into the in-memory stores. Always runs at
// startup (unlike vault/persist.ts's loadFromVault, which only runs once a
// filesystem vault is manually mounted) so the merged inbox has last-sync
// data immediately, and sync/session.ts's querystate-driven delta sync kicks
// in instead of a full historical re-fetch.
export async function loadFromCache(): Promise<void> {
  try {
    const [msgs, thrs, mbx, ids] = await Promise.all([
      idb.getAll(idb.STORES.messages),
      idb.getAll(idb.STORES.threads),
      idb.getAll(idb.STORES.mailboxes),
      idb.getAll(idb.STORES.identities),
    ])
    for (const m of msgs) messages.put(m as Email)
    for (const t of thrs) threads.put(t as Thread)
    if (mbx.length) mailboxes.set(mbx[0] as Mailbox[])
    if (ids.length) identities.set(ids[0] as Identity[])
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

// Purge one identity's cached messages + sync cursors across all its relays
// (mail + AP) — called from per-account "Log out" so a removed identity's
// data can't resurrect from cache if it (or another identity in the same
// browser) reconnects later.
export async function clearIdentity(identity: string): Promise<void> {
  const accts = new Set(messages.forIdentity(identity).map(e => messages.accountOf(e)))
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
