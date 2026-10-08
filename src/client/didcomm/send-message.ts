// Outbound DIDComm chat: a Basic Message 2.0 from this device's own key in
// the identity's DID document, to the recipient's public DID (its every
// keyAgreement key, Forward-wrapped through its mediator when it names one --
// front-door-send.ts). One message to one recipient; a group message is the
// same plaintext, `to` listing every participant, sent to each of them in
// turn (DIDComm v2.1: "Encrypt M for each party that is an intended
// recipient"). Network-only: the local "sent" copy is the caller's job.
import { PING_RESPONSE, isPing, responseOwedFor } from '../../protocol/didcomm/trust-ping.ts'
import type { DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { BASIC_MESSAGE } from './basicmessage.ts'
import { defaultFetch } from '../../protocol/net-fetch.ts'
import { sendFrontDoorMessage, type DidCommSendResult, type SendDidCommMessageOptions } from './front-door-send.ts'

export { type DidCommSendResult }

export interface ChatMessageOptions extends SendDidCommMessageOptions {
  /** When the message was written (ISO, ms). The `sentAt` extension and the
   * official `created_time` header both come from it; a retry of a queued
   * message keeps its original time. Defaults to now. */
  sentAt?: string
}

/** Sends a chat message to `toDid`. `opts.id` keeps a retried message's
 * DIDComm id stable; `opts.thid` and `opts.audience` make it part of a group
 * conversation (the thread and its participants). */
export async function sendDidCommMessage(toDid: string, content: string, opts: ChatMessageOptions): Promise<DidCommSendResult> {
  const sentAt = opts.sentAt ?? new Date().toISOString()
  return sendFrontDoorMessage(toDid, BASIC_MESSAGE, {
    content, sentAt, ...(opts.subject ? { subject: opts.subject } : {}),
  }, { ...opts, createdTime: Math.floor(Date.parse(sentAt) / 1000) })
}

/** Trust Ping 2.0: answers a received ping that asked for a response (the
 * default), threaded to it, to the DID it came from, from the key it reached
 * (the front door, or a DID this identity rotated to). Null when no answer
 * is owed. */
export async function answerTrustPing(
  ping: DidCommPlaintext,
  options: { key: { fromKid: string; x25519PrivateKey: Uint8Array }; fetch?: typeof fetch },
): Promise<DidCommSendResult | null> {
  if (!isPing(ping) || !responseOwedFor(ping) || typeof ping.from !== 'string') return null
  return sendFrontDoorMessage(ping.from, PING_RESPONSE, {}, { ...options.key, thid: ping.id, fetch: options.fetch ?? defaultFetch() })
}
