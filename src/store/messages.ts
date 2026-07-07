import type { Email } from 'jmap-rfc-types'

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

// The identity (email) a message belongs to, independent of which relay it came
// from. Set at ingest alongside `_account` (the per-relay storage key). Used to
// build the merged inbox view that unifies an identity's relays.
export function identityOf(email: Email): string {
  return (email as any)._identity as string ?? accountOf(email)
}

export function forIdentity(identity: string): Email[] {
  return [...store.values()].filter(e => identityOf(e) === identity)
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
