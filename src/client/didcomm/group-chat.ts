// DIDComm group chat with nothing but DIDComm v2.1 itself: a thread of Basic
// Messages whose `to` lists more than one party (PLAN-refactor.md §8). The
// plaintext `to` names every participant by public DID, the way an email's
// To/Cc does; each participant gets the same plaintext encrypted for them
// alone; `thid` is the conversation. There is no group protocol, no invite,
// no roster store, and no administrator -- the participants of a group are
// whoever its latest message was addressed to (plus its sender), and adding
// or dropping someone is sending the next message to a different `to`.
import type { LocalJmapEmail } from '../store/projection/gateway.ts'

const GROUP_ADDRESS_PREFIX = 'didcomm-group:'

/** The local thread id of the group conversation `thid`. */
export function didcommGroupAddress(thid: string): string {
  return `${GROUP_ADDRESS_PREFIX}${thid}`
}

/** Inverse of `didcommGroupAddress`. Throws on anything not shaped like
 * one -- every call site already gates entry on `startsWith(...)` first. */
export function parseDidCommGroupAddress(address: string): string {
  if (!address.startsWith(GROUP_ADDRESS_PREFIX)) throw new TypeError(`not a DIDComm group address: ${address}`)
  return address.slice(GROUP_ADDRESS_PREFIX.length)
}

/** Whether a received message is part of a group conversation: it was
 * addressed to more than one party. One recipient (or none, read as the
 * recipient alone, like Bcc) is a 1:1 message. */
export function isGroupAudience(to: readonly string[] | undefined): boolean {
  return (to?.length ?? 0) > 1
}

/** The group conversation `thid` as this device has it: its participants
 * (every DID its LATEST message names -- sender and recipients, this
 * identity included) and its name (the latest subject given). A message
 * that is older than the latest never decides who is in the group, so
 * someone dropped from it is not brought back by replying to an old one.
 * Null when there is no such conversation. */
export function groupConversation(
  thid: string,
  emails: readonly LocalJmapEmail[],
): { participants: string[]; name?: string } | null {
  const threadId = didcommGroupAddress(thid)
  const messages = emails.filter(email => email.threadId === threadId)
    .sort((left, right) => (left.sentAt ?? left.receivedAt).localeCompare(right.sentAt ?? right.receivedAt) || left.id.localeCompare(right.id))
  const latest = messages.at(-1)
  if (!latest) return null
  const participants = new Set<string>()
  for (const address of [...(latest.from ?? []), ...(latest.to ?? [])]) {
    if (address.email?.startsWith('did:')) participants.add(address.email)
  }
  const name = [...messages].reverse().find(message => message.subject)?.subject
  return { participants: [...participants].sort(), ...(name ? { name } : {}) }
}
