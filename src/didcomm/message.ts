// DIDComm plaintext-message envelope shape (message_structure.md). Ported
// from src.bak/did/didcomm/message.ts, trimmed to what this rewrite's
// inbound-only ingress projector needs: the envelope shape itself and the
// two pure helpers (buildPlaintext, isExpired). Dropped relative to the
// source: sendAndUnpack and its MediatorLike/DidCommSender/publicKeyOf/
// mlkemPublicKeyOf support -- that was the old synchronous "POST, get an
// inline authcrypt'd reply in the same HTTP response" mediator round-trip,
// which this rewrite's store-and-pull architecture doesn't have (a device
// pulls asynchronously via the shared IngressStore, same as mail -- there is
// no synchronous reply channel to unpack a response from). Outbound DIDComm
// sending is separate, later work (the same split mail.ts already has
// between MailIngressProjector and identity/bootstrap.ts's
// buildMailSubmitter).
export interface DidCommPlaintext {
  id: string
  typ: string
  type: string
  body: unknown
  from?: string
  to?: string[]
  // Threading (threading.md): thid identifies the thread, pthid the parent
  // thread. Absent thid means "id IS the thid" per spec.
  thid?: string
  pthid?: string
  // ack (problems.md "ACKs"): ids of prior messages this one acknowledges --
  // only ever in answer to a `please_ack` (mediator/server.ts's problemReply).
  ack?: string[]
  // please_ack: the sender asking to be told the message arrived. Read, not
  // written -- biset never requests one, but the mediator must recognize one
  // to know when answering with `ack` is warranted.
  please_ack?: string[]
  // created_time is spec-recommended on every message; expires_time is set
  // only when a sender wants a deadline. Both are UTC epoch SECONDS as
  // integers (message_structure.md) -- NOT millis, a common interop trap.
  created_time?: number
  expires_time?: number
  // Pickup 3.0 `delivery`'s queued messages ride as attachments, each id
  // being the mediator's own queue id (mediator/server.ts's DELIVERY_REQUEST).
  attachments?: Array<{ id: string; data: { json: unknown } }>
}

/** UTC epoch seconds as an integer -- the unit every DIDComm time header uses. */
function nowEpochSeconds(): number { return Math.floor(Date.now() / 1000) }

export interface PlaintextOptions {
  id?: string
  createdTime?: number
  thid?: string
  pthid?: string
  ack?: string[]
  /** UTC epoch seconds. Omit for no expiry (the sender's default per spec). */
  expiresTime?: number
}

export function buildPlaintext(type: string, body: unknown, from?: string, to?: string, opts: PlaintextOptions = {}): DidCommPlaintext {
  const msg: DidCommPlaintext = {
    id: opts.id ?? crypto.randomUUID(),
    typ: 'application/didcomm-plain+json',
    type, body,
    created_time: opts.createdTime ?? nowEpochSeconds(),
  }
  if (from) msg.from = from
  if (to) msg.to = [to]
  if (opts.thid) msg.thid = opts.thid
  if (opts.pthid) msg.pthid = opts.pthid
  if (opts.ack && opts.ack.length) msg.ack = opts.ack
  if (opts.expiresTime !== undefined) msg.expires_time = opts.expiresTime
  return msg
}

/** True if the message declares an `expires_time` already in the past. A
 * small skew allowance absorbs clock divergence between sender and receiver.
 * A message with no expires_time never expires (returns false). */
export function isExpired(msg: { expires_time?: number }, skewSeconds = 60): boolean {
  return typeof msg.expires_time === 'number' && msg.expires_time + skewSeconds < nowEpochSeconds()
}
