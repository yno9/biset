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

/** Drops one thread — the counterpart to messages.ts's remove(), for
 * cache.ts's clearIdentity to purge a deleted identity's thread groupings
 * along with its messages (previously only messages/querystate were
 * cleared, so a thread's own cached row — and with it its stale "hi" /
 * "Encrypted message" preview — survived a full identity delete intact). */
export function remove(id: string): void {
  store.delete(id)
}

/** Drops everything. For logout (app.ts), which no longer reloads the page —
 * so in-memory state has to be emptied explicitly rather than dying with the
 * document. */
export function clear(): void {
  store.clear()
}
