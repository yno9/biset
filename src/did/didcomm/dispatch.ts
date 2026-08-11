// Inbound protocol dispatcher: the single place that decides how a RECEIVED
// DIDComm plaintext should be reacted to, independent of biset's UI. It answers
// two questions a receiver needs:
//   - protocolResponseFor: does this message oblige an automatic protocol reply
//     (trust-ping → ping-response, discover-features/queries → disclose)?
//   - classifyInbound: what kind of message is this, so the caller (channel.ts)
//     can route a chat message to the inbox and everything else to protocol
//     handling?
//
// Keeping this pure and biset-agnostic means the same logic drives the client's
// poll loop and could drive a standalone agent — no store/session dependencies.
import type { DidCommPlaintext } from './message.ts'
import type { SendOptions } from './send.ts'
import { isPing, pingResponseFor } from './trust-ping.ts'
import { isQueries, discloseFor, type Disclosure } from './discover-features.ts'
import { isProblemReport, formatProblem, type ProblemBody } from './problems.ts'

const BASICMESSAGE_PREFIX = 'https://didcomm.org/basicmessage/2.0'

export type InboundKind = 'chat' | 'trust-ping' | 'discover-features' | 'problem-report' | 'other'

export function classifyInbound(msg: { type?: string }): InboundKind {
  const t = msg.type ?? ''
  if (t.startsWith(BASICMESSAGE_PREFIX)) return 'chat'
  if (t.startsWith('https://didcomm.org/trust-ping/2.0')) return 'trust-ping'
  if (t.startsWith('https://didcomm.org/discover-features/2.0')) return 'discover-features'
  if (isProblemReport(msg)) return 'problem-report'
  return 'other'
}

export interface InboundReply { toDid: string; options: SendOptions }

/** The automatic protocol reply this agent owes for a received message, or null
 * when none is warranted (a chat message, a problem-report, a ping-response, a
 * disclose, or an unknown type — all either terminal or for the app to handle).
 * `senderDid` is who to address the reply to (the authenticated sender). */
export function protocolResponseFor(msg: DidCommPlaintext, senderDid: string, registry?: Disclosure[]): InboundReply | null {
  if (isPing(msg)) {
    const options = pingResponseFor(msg)
    return options ? { toDid: senderDid, options } : null
  }
  if (isQueries(msg)) return { toDid: senderDid, options: discloseFor(msg, registry) }
  return null
}

/** A received problem-report as human text (code + interpolated comment), for
 * logging/surfacing. */
export function describeProblem(msg: DidCommPlaintext): string {
  return formatProblem((msg.body ?? {}) as ProblemBody)
}
