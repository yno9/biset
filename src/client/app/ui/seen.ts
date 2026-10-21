// Reading: what an open thread holds that was not read before is marked read ($seen) once it has been on screen.
/** Set by main.ts, which owns the store. */
type MarkSeenHandler = (messages: ReadonlyArray<{ jmap_id: string }>) => void
let onMarkSeen: MarkSeenHandler | undefined
export function setMarkSeenHandler(handler: MarkSeenHandler | undefined): void { onMarkSeen = handler }
const marking = new Set<string>()
/** The open thread's messages that are not read yet are read now. Asked again for the same message while it is being marked, it waits. */
export function markSeen(messages: ReadonlyArray<{ jmap_id: string; seen?: boolean }>): void {
  const fresh = messages.filter(message => message.seen !== true && !marking.has(message.jmap_id))
  if (!fresh.length || !onMarkSeen) return
  for (const message of fresh) marking.add(message.jmap_id)
  onMarkSeen(fresh)
}
/** The message is read as far as the store goes: marking it again is allowed (it would be a no-op). */
export function markSeenDone(ids: readonly string[]): void { for (const id of ids) marking.delete(id) }

