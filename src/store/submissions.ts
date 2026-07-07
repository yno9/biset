import type { PendingSubmission } from '../types.ts'

const store = new Map<string, PendingSubmission>()

export function get(id: string): PendingSubmission | undefined {
  return store.get(id)
}

export function all(): PendingSubmission[] {
  return [...store.values()]
}

export function put(sub: PendingSubmission): void {
  store.set(sub.id, sub)
}

export function remove(id: string): void {
  store.delete(id)
}
