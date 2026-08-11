import type { Email } from 'jmap-rfc-types'
import { relaysForId, accountKey } from '../context.ts'

// JMAP email ids are unique only WITHIN one account. With multiple accounts on the
// same server, two accounts can share an id string, so the store is keyed by
// (owning account, id). Each stored Email carries a non-JMAP `_account` stamp set
// at ingest time (session.ts); persistence and all lookups honour it. Without this
// partitioning, one account's mail overwrites another's and gets rendered under the
// wrong account → wrong decryption key → "暗号化メッセージ".

const store = new Map<string, Email>()

// Reads the account stamp placed on the email at ingest.
export function accountOf(email: Email): string {
  return (email as any)._account as string ?? ''
}

function keyOf(account: string, id: string): string {
  return `${account}\0${id}`
}

export function get(account: string, id: string): Email | undefined {
  return store.get(keyOf(account, id))
}

export function all(): Email[] {
  return [...store.values()]
}

// All emails owned by one account.
export function forAccount(account: string): Email[] {
  return [...store.values()].filter(e => accountOf(e) === account)
}

// Every message belonging to one identity (DID, or email fallback for a
// DID-less relay) — spans every relay/address that identity currently has a
// live session on. Computed dynamically from `sessions` (relaysForId) rather
// than a stamped `_identity` field: a message only ever needs to know its own
// `_account`, and "which accounts share this identity" is exactly what
// relaysForId already answers on demand — the same organize-don't-duplicate
// principle did/contacts.ts's contact-DID grouping uses for correspondents,
// applied to the user's own multi-relay identity instead. This also means a
// lazily-DID-migrated identity's older messages (ingested before the account
// had a DID) are picked up correctly with no re-stamping needed — `_account`
// never changes, only which identity currently claims it.
export function forIdentity(identity: string): Email[] {
  const accounts = new Set(relaysForId(identity).map(s => accountKey(s.account)))
  return [...store.values()].filter(e => accounts.has(accountOf(e)))
}

export function byThread(account: string, threadId: string): Email[] {
  return [...store.values()].filter(e => accountOf(e) === account && e.threadId === threadId)
}

export function put(email: Email): void {
  store.set(keyOf(accountOf(email), email.id as string), email)
}

export function remove(account: string, id: string): void {
  store.delete(keyOf(account, id))
}
