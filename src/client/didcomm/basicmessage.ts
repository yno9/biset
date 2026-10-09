// Basic Message Protocol 2.0 (basicmessage.md): the one DIDComm message type
// this rewrite treats as chat, everything else (trust-ping, future OOB/
// control) staying a protocol message that never becomes a thread row.
// Ported in spirit from src.bak/did/didcomm/channel.ts's own basicmessage
// handling -- narrowed to the message shape alone; that file's mediator
// queue polling, group conversations, push wake-up, and DID rotation are
// out of scope here (this rewrite's DIDComm adapter is external-ingress/
// OOB/bootstrap/control plus, now, 1:1 chat -- not the old system's full
// messaging subsystem, confirmed with the user).
import type { MailAuthResults } from '../store/projection/gateway.ts'

export const BASIC_MESSAGE = 'https://didcomm.org/basicmessage/2.0/message'

export function isBasicMessage(msg: { type?: string }): boolean { return msg.type === BASIC_MESSAGE }

export interface BasicMessageBody {
  content: string
  /** NOT part of basicmessage/2.0 (whose only attribute is `content`): a biset
   * extension. An ISO millisecond timestamp, for the order of messages sent
   * within one second -- the official `created_time` header is epoch seconds.
   * Always from the same instant as `created_time` (and, for a bridged mail,
   * the mail's own `Date:`). Optional: a sender without it is read by its
   * `created_time`. */
  sentAt?: string
  /** NOT part of basicmessage/2.0: a biset extension, the subject line of a
   * mail-shaped message. A receiver that does not know it ignores it. */
  subject?: string
  /** NOT part of basicmessage/2.0: the sender's display name (a bridged
   * mail's `From:` name, didmail PROTOCOL.md §4). */
  fromName?: string
  /** NOT part of basicmessage/2.0: the DID a reply goes to instead of `from`
   * (a bridged mail's `Reply-To:`, didmail PROTOCOL.md §4.2). */
  replyTo?: string
  /** NOT part of basicmessage/2.0: a bridged mail's SPF/DKIM/DMARC results
   * (didmail PROTOCOL.md §4.3). Unknown fields and values are dropped. */
  auth?: MailAuthResults
}

/** RFC 8601's result words. */
const AUTH_RESULTS = new Set(['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'])

function mailAuthOf(value: unknown): MailAuthResults | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const auth = value as Record<string, unknown>
  const result: MailAuthResults = {}
  for (const field of ['spf', 'dkim', 'dmarc'] as const) {
    const entry = auth[field]
    if (typeof entry === 'string' && AUTH_RESULTS.has(entry)) result[field] = entry
  }
  if (typeof auth.domain === 'string' && auth.domain) result.domain = auth.domain
  return Object.keys(result).length ? result : undefined
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
  const { sentAt, subject, fromName, replyTo } = body as Record<string, unknown>
  const auth = mailAuthOf((body as Record<string, unknown>).auth)
  return {
    content,
    ...(typeof sentAt === 'string' ? { sentAt } : {}),
    ...(typeof subject === 'string' ? { subject } : {}),
    ...(typeof fromName === 'string' && fromName ? { fromName } : {}),
    ...(typeof replyTo === 'string' && replyTo.startsWith('did:') ? { replyTo } : {}),
    ...(auth ? { auth } : {}),
  }
}
