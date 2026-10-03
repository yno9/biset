// DIDComm plaintext-message envelope shape (message_structure.md) and its
// pure helpers: building one, expiry, and the addressing-consistency checks
// every unpacker applies. Talking to a mediator is mediator-transport.ts;
// delivering to a recipient is client/didcomm/front-door-send.ts.
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
  // from_prior (DID Rotation): a JWT from the sender's previous DID naming
  // `from` as its successor (from-prior.ts).
  from_prior?: string
  // return_route (DIDComm v2.1 transports / Pickup 3.0): "all" asks the
  // receiver to answer on the same connection -- the HTTP response or the
  // open WebSocket -- instead of the sender's own service endpoint.
  return_route?: 'all' | 'none' | 'thread'
  // created_time is spec-recommended on every message; expires_time is set
  // only when a sender wants a deadline. Both are UTC epoch SECONDS as
  // integers (message_structure.md) -- NOT millis, a common interop trap.
  created_time?: number
  expires_time?: number
  // Pickup 3.0 `delivery`'s queued messages ride as attachments, each id
  // being the mediator's own queue id (mediator/server.ts's DELIVERY_REQUEST).
  attachments?: Array<{
    id: string
    media_type?: string
    data: { json?: unknown; base64?: string }
  }>
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
  attachments?: DidCommPlaintext['attachments']
  fromPrior?: string
  returnRoute?: DidCommPlaintext['return_route']
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
  if (opts.attachments?.length) msg.attachments = opts.attachments
  if (opts.fromPrior) msg.from_prior = opts.fromPrior
  if (opts.returnRoute) msg.return_route = opts.returnRoute
  return msg
}

/** True if the message declares an `expires_time` already in the past. A
 * small skew allowance absorbs clock divergence between sender and receiver.
 * A message with no expires_time never expires (returns false). */
export function isExpired(msg: { expires_time?: number }, skewSeconds = 60): boolean {
  return typeof msg.expires_time === 'number' && msg.expires_time + skewSeconds < nowEpochSeconds()
}

/** The DID part of a DID URL (`did:x:y#key-1` → `did:x:y`). */
function didOfUrl(didUrl: string): string { const hash = didUrl.indexOf('#'); return hash === -1 ? didUrl : didUrl.slice(0, hash) }

/**
 * Message Layer Addressing Consistency (DIDComm Messaging v2.1): for an
 * authcrypt message, the plaintext `from` is REQUIRED, MUST be a DID (or DID
 * URL) without a fragment, and MUST match the encryption layer's `skid` -- a
 * mismatch MUST be an error. `senderKid` is the `skid` the authcrypt layer
 * just authenticated; `from` is only the sender's own claim, so anything that
 * acts on "who sent this" must have checked the two agree first. Without
 * this, a party holding ANY valid key could authenticate as itself and still
 * name somebody else in `from` (found 2026-10-02: the mediator authorized
 * keylist-update/messages-received by `from`, letting one client deregister
 * another's key and drop its queue).
 */
export function assertFromMatchesSender(msg: { from?: unknown }, senderKid: string): void {
  if (typeof msg.from !== 'string' || !msg.from) throw new DidCommSenderMismatchError('an authcrypt message must name its sender in `from`')
  if (msg.from.includes('#')) throw new DidCommSenderMismatchError('`from` must be a DID without a fragment')
  if (didOfUrl(senderKid) !== msg.from) throw new DidCommSenderMismatchError(`\`from\` (${msg.from}) does not match the authenticated sender (${senderKid})`)
}

/** True when `to` is absent (each recipient then assumes it is the only one) or
 * names the DID that `ownKid` belongs to. The spec says a recipient SHOULD check
 * this and warn, and MUST NOT reject the message for it. */
export function addressedTo(msg: { to?: unknown }, ownKid: string): boolean {
  if (!Array.isArray(msg.to)) return true
  const own = didOfUrl(ownKid)
  return msg.to.some(value => typeof value === 'string' && didOfUrl(value) === own)
}

export class DidCommSenderMismatchError extends Error {}
