import type { Thread } from 'jmap-rfc-types'

const store = new Map<string, Thread>()

export function get(id: string): Thread | undefined {
  return store.get(id)
}

export function all(): Thread[] {
  return [...store.values()]
}

export function put(thread: Thread): void {
  store.set(thread.id as string, thread)
}
