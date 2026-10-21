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
import { bytesToBase64url } from '../../protocol/canonical.ts'
import { sendFrontDoorMessage, type DidCommSendResult, type SendDidCommMessageOptions } from './front-door-send.ts'

export { type DidCommSendResult }

export interface ChatMessageOptions extends SendDidCommMessageOptions {
  /** When the message was written (ISO, ms). The `sentAt` extension and the
   * official `created_time` header both come from it; a retry of a queued
   * message keeps its original time. Defaults to now. */
  sentAt?: string
  /** This identity's OpenPGP key, for a mail bridge to put in an `Autocrypt:` header (didmail PROTOCOL.md §7.4). */
  autocrypt?: { keydata: string; preferEncrypt?: 'mutual' }
  /** The message, already encrypted (pgp/compose.ts): a mail bridge wraps this armored OpenPGP message into PGP/MIME
   * (didmail PROTOCOL.md §7.4). `content` is then not sent. */
  encrypted?: { armored: string }
  /** This is the first message to an address that has not written to us -- the user chose to write first (didmail PROTOCOL.md §7.1). */
  introduction?: boolean
}

/** Sends a chat message to `toDid`. `opts.id` keeps a retried message's
 * DIDComm id stable; `opts.thid` and `opts.audience` make it part of a group
 * conversation (the thread and its participants). */
export async function sendDidCommMessage(toDid: string, content: string, opts: ChatMessageOptions): Promise<DidCommSendResult> {
  const sentAt = opts.sentAt ?? new Date().toISOString()
  const encrypted = opts.encrypted
  return sendFrontDoorMessage(toDid, BASIC_MESSAGE, {
    content: encrypted ? '' : content, sentAt, ...(opts.subject ? { subject: opts.subject } : {}), ...(opts.autocrypt ? { autocrypt: opts.autocrypt } : {}),
    ...(encrypted ? { encryption: 'openpgp' } : {}),
    ...(opts.introduction ? { introduction: true } : {}),
  }, {
    ...opts, createdTime: Math.floor(Date.parse(sentAt) / 1000),
    ...(encrypted ? { attachments: [{ id: 'pgp', filename: 'encrypted.asc', media_type: 'application/octet-stream', data: { base64: bytesToBase64url(new TextEncoder().encode(encrypted.armored)) } }] } : {}),
  })
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
