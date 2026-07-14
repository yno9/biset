import type { Card } from '../did/contacts.ts'

let store: Card[] = []

export function all(): Card[] {
  return store
}

export function set(list: Card[]): void {
  store = list
}

// Upserts one Card by uid — contacts arrive one at a time as they're resolved
// (unlike mailboxes/identities, which sync as a full authoritative list).
export function put(card: Card): void {
  const i = store.findIndex(c => c.uid === card.uid)
  if (i >= 0) store[i] = card
  else store.push(card)
}

export function byUid(uid: string): Card | undefined {
  return store.find(c => c.uid === uid)
}
