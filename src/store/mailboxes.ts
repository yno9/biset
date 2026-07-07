import type { Mailbox } from 'jmap-rfc-types'

let store: Mailbox[] = []

export function all(): Mailbox[] {
  return store
}

export function set(list: Mailbox[]): void {
  store = list
}

export function byId(id: string): Mailbox | undefined {
  return store.find(m => (m.id as string) === id)
}

export function byName(name: string): Mailbox | undefined {
  return store.find(m => m.name === name)
}
