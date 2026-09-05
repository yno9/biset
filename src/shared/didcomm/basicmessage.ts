// Basic Message Protocol 2.0 (basicmessage.md): the one DIDComm message type
// this rewrite treats as chat, everything else (trust-ping, future OOB/
// control) staying a protocol message that never becomes a thread row.
// Ported in spirit from src.bak/did/didcomm/channel.ts's own basicmessage
// handling -- narrowed to the message shape alone; that file's mediator
// queue polling, group conversations, push wake-up, and DID rotation are
// out of scope here (this rewrite's DIDComm adapter is external-ingress/
// OOB/bootstrap/control plus, now, 1:1 chat -- not the old system's full
// messaging subsystem, confirmed with the user).
export const BASIC_MESSAGE = 'https://didcomm.org/basicmessage/2.0/message'

export function isBasicMessage(msg: { type?: string }): boolean { return msg.type === BASIC_MESSAGE }

export interface BasicMessageBody {
  content: string
  /** biset extension (not part of the DIDComm spec), matching src.bak's own
   * basicmessage `sentAt` field: an ISO millisecond timestamp for
   * same-second ordering `created_time`'s epoch-seconds precision can't
   * give. Omitted, not required -- a non-biset sender's `created_time`
   * remains the fallback (message.ts's own header-level field). */
  sentAt?: string
  subject?: string
}

/** One thread per correspondent DID pair, not per-subject like mail -- a
 * chat's whole point is one continuous conversation, matching src.bak's own
 * threadIdFor. Order-independent (sorted) so both correspondents' devices
 * derive the identical id. */
export function didCommThreadId(selfDid: string, otherDid: string): string {
  return [selfDid, otherDid].sort().join('|')
}

export function basicMessageBodyOf(msg: { body?: unknown }): BasicMessageBody | null {
  const body = msg.body
  if (typeof body !== 'object' || body === null) return null
  const content = (body as Record<string, unknown>).content
  if (typeof content !== 'string') return null
  const sentAt = (body as Record<string, unknown>).sentAt
  const subject = (body as Record<string, unknown>).subject
  return {
    content,
    ...(typeof sentAt === 'string' ? { sentAt } : {}),
    ...(typeof subject === 'string' ? { subject } : {}),
  }
}
