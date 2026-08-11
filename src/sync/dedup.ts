import type { Email } from 'jmap-rfc-types'
import * as messages from '../store/messages.ts'

// Returns only emails whose messageId is not already in the store.
// Emails with no messageId are always considered new.
export function filterNew(emails: Email[]): Email[] {
  const existing = messages.all()
  const seenMessageIds = new Set(
    existing.flatMap(e => (e.messageId as string[] | undefined) ?? [])
  )
  return emails.filter(e => {
    const ids = (e.messageId as string[] | undefined) ?? []
    return ids.length === 0 || ids.every(id => !seenMessageIds.has(id))
  })
}
