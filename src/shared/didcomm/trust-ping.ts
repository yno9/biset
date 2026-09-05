// Trust Ping Protocol 2.0 (trustping.md): a transport-agnostic way to test
// that a DIDComm channel is live and the encryption round-trips. Ported from
// src.bak/did/didcomm/trust-ping.ts, message shapes only -- the source
// file's own SendOptions-typed pingOptions (for emitting a ping) isn't
// ported since this rewrite has no outbound DIDComm sender yet (this
// file's own package header, message.ts).
import type { DidCommPlaintext } from './message.ts'

export const PING = 'https://didcomm.org/trust-ping/2.0/ping'
export const PING_RESPONSE = 'https://didcomm.org/trust-ping/2.0/ping-response'

export function isPing(msg: { type?: string }): boolean { return msg.type === PING }
function isPingResponse(msg: { type?: string }): boolean { return msg.type === PING_RESPONSE }

/** Whether a `ping-response` is owed for a received `ping`, threaded to it
 * via `thid` when the caller does send one. `false` when the ping set
 * response_requested:false (no reply owed). A ping with response_requested
 * absent defaults to true (reply owed) per trustping.md. */
export function responseOwedFor(ping: DidCommPlaintext): boolean {
  const responseRequested = (ping.body as { response_requested?: boolean } | undefined)?.response_requested
  return responseRequested !== false
}
