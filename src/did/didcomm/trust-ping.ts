// Trust Ping Protocol 2.0 (trustping.md): a transport-agnostic way to test that
// a DIDComm channel is live and the encryption round-trips. `sender` emits a
// `ping`; `receiver` replies with a `ping-response` threaded to it (unless the
// ping set response_requested:false). The reply-sending is done by the inbound
// dispatcher (dispatch.ts) — this module owns only the message shapes and the
// pure "given a ping, what response (if any)?" decision.
import type { SendOptions } from './send.ts'
import type { DidCommPlaintext } from './message.ts'

export const PING = 'https://didcomm.org/trust-ping/2.0/ping'
export const PING_RESPONSE = 'https://didcomm.org/trust-ping/2.0/ping-response'

export function isPing(msg: { type?: string }): boolean { return msg.type === PING }
export function isPingResponse(msg: { type?: string }): boolean { return msg.type === PING_RESPONSE }

/** A `ping`. `responseRequested` defaults to true (trustping.md); pass false to
 * ping without asking for a reply (a pure liveness poke of the receiver). */
export function pingOptions(responseRequested = true, comment?: string): SendOptions {
  const body: { response_requested: boolean; comment?: string } = { response_requested: responseRequested }
  if (comment) body.comment = comment
  return { type: PING, body }
}

/** The `ping-response` to send for a received `ping`, threaded to the ping via
 * `thid` — or null when the ping set response_requested:false (no reply owed).
 * A ping with response_requested absent defaults to true (reply owed). */
export function pingResponseFor(ping: DidCommPlaintext): SendOptions | null {
  const responseRequested = (ping.body as { response_requested?: boolean } | undefined)?.response_requested
  if (responseRequested === false) return null
  return { type: PING_RESPONSE, body: {}, headers: { thid: ping.id } }
}
