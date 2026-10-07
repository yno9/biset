// The DIDComm v2 mediator: Coordinate Mediation 3.0, Routing 2.0, Pickup 3.0,
// Discover Features 2.0, Trust Ping 2.0.
// A client that can't hold a socket open (a browser) registers here, gives
// the mediator's URL out as its own DIDComm endpoint, and collects what
// arrives whenever it's next running.
//
// Two transports, one message handler: HTTPS POST and WebSocket. Neither
// carries trust -- every message is authcrypt'd (or a Forward's anoncrypt)
// on its own. A reply goes back on the same connection only when the
// request asked with `return_route: "all"`; otherwise there is nowhere to
// send it (a browser has no endpoint) and it is dropped. Pickup 3.0 live
// mode (`live-delivery-change`) works only on a WebSocket: new copies for
// that inbox are pushed there as `delivery` messages and stay queued until
// the device acks them, exactly like a polled delivery.
//
// Blind by construction: no import from the client, `roster/` or `vault/`,
// and it cannot decrypt a byte it relays. A separate deploy unit on purpose
// (src/server/mediator/index.ts).
//
// ## Who may register what
//
// Every request is authcrypt'd, so the mediator knows which KEY sent it.
// Registering recipient DID X (recipient-update add) is allowed exactly when
// that key is one of X's own keyAgreement keys -- holding X's private key IS
// the proof of owning X. Coordinate Mediation 3.0 leaves this check out
// (3.0 names it under "Future Considerations"); without it anyone could
// register someone else's public DID here and collect copies of their
// traffic or block their registration.
//
// Ownership says nothing about WHICH of X's devices is asking, and a
// relationship did:peer shares one key across all of them, so a request MAY
// also name its inbox with a `device` label (a biset extension field): one
// inbox per (X, device), at most `maxDevicesPerDid` per X. A request without
// `device` -- every standard client's -- uses the inbox derived from its own
// sending key (`defaultDeviceLabel`). A Forward for X is copied into every
// live inbox of X (routing.md lets a mediator multiplex to a recipient's
// several physical devices).
//
// did:peer keys are read straight out of the DID. did:webvh keys are learned
// the way any DIDComm agent learns a sender's keys: the mediator resolves the
// DID (`resolveWebvh`, webvh-state.ts) and re-checks it from time to time --
// a newer log revokes every inbox registered with a key it no longer lists.
// Without a `resolveWebvh` it falls back to the latest log a client pushed to
// `POST /webvh-log` (not DIDComm; see webvh-state.ts).
import { decodePeerDid2, publicKeyOf, type PeerIdentity } from '../../protocol/didcomm/peer.ts'
import { assertFromMatchesSender, buildPlaintext, isExpired, type DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { buildProblemReport, PROBLEM_REPORT } from '../../protocol/didcomm/problems.ts'
import {
  packAuthcrypt, unpackAuthcrypt, unpackAnoncrypt, parseJwe, protectedHeaderOf, b64url,
  DIDCOMM_ENCRYPTED_MEDIA_TYPE, isDidCommEncryptedRequest,
} from '../../protocol/didcomm/crypto.ts'
import { decodeX25519Multikey } from '../../protocol/didcomm/multikey.ts'
import { defaultDeviceLabel } from '../../protocol/didcomm/mediator-device.ts'
import { webvhStateFromLog, WebvhUnavailable, type WebvhStateResolver } from './webvh-state.ts'
import { peerMediatorIdentity, type MediatorIdentity } from './identity.ts'
import { packSigned } from './signature.ts'
import { PING, PING_RESPONSE, TRUST_PING, responseOwedFor } from '../../protocol/didcomm/trust-ping.ts'
import {
  isDeviceLabel, MediatorFullError, MessageTooBigError, QueueFullError, TooManyDevicesError,
  type QueuedMessage, type SqliteMediatorStore,
} from './sqlite-store.ts'
import {
  COORDINATE_MEDIATION, MEDIATE_REQUEST, MEDIATE_GRANT, RECIPIENT_UPDATE, RECIPIENT_UPDATE_RESPONSE, RECIPIENT_QUERY, RECIPIENT,
  ROUTING, FORWARD, MESSAGE_PICKUP, STATUS_REQUEST, STATUS, DELIVERY_REQUEST, DELIVERY, MESSAGES_RECEIVED,
  LIVE_DELIVERY_CHANGE, LIVE_MODE_NOT_SUPPORTED_PROBLEM, MAX_DEVICES_PROBLEM,
  DISCOVER_FEATURES, DISCOVER_FEATURES_QUERIES, DISCOVER_FEATURES_DISCLOSE, MAX_RECEIVE_BYTES, MESSAGE_TOO_BIG_PROBLEM,
} from '../../protocol/didcomm/mediator-protocol.ts'

function didOf(didOrKidUrl: string): string {
  const i = didOrKidUrl.indexOf('#')
  return i === -1 ? didOrKidUrl : didOrKidUrl.slice(0, i)
}

const utf8 = (s: string) => new TextEncoder().encode(s)
const toHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')
const fromHex = (h: string): Uint8Array => new Uint8Array((h.match(/../g) ?? []).map(x => parseInt(x, 16)))

export interface MediatorOptions {
  /** A did:web mediator (identity.ts), or a bare did:peer. */
  mediator: MediatorIdentity | PeerIdentity
  store: SqliteMediatorStore
  /** The largest DIDComm message this mediator takes (Discover Features
   * `max_receive_bytes`). Defaults to the store's per-message limit; a
   * deployment with a smaller request-body limit passes the smaller one. */
  maxReceiveBytes?: number
  /** How to learn a did:webvh's current keys: resolve its log. Absent: only
   * logs pushed to `POST /webvh-log` are known (the mediator never dials out). */
  resolveWebvh?: WebvhStateResolver
  /** A resolved state is trusted this long before the DID is resolved again (default 5 min). */
  webvhFreshMs?: number
  /** After a resolution attempt (any outcome), the same DID is not tried again for this long (default 10 s). */
  webvhRetryMs?: number
  /** When resolution fails, the state held is still used if it was confirmed this recently (default 1 h). */
  webvhStaleMs?: number
  now?: () => number
}

/** What a Discover Features query may match: the protocols this mediator
 * speaks (with its role), the headers it honours, and its constraint. */
function mediatorFeatures(maxReceiveBytes: number): Array<Record<string, unknown> & { 'feature-type': string; id: string }> {
  return [
    { 'feature-type': 'protocol', id: COORDINATE_MEDIATION, roles: ['mediator'] },
    { 'feature-type': 'protocol', id: ROUTING, roles: ['mediator'] },
    { 'feature-type': 'protocol', id: MESSAGE_PICKUP, roles: ['mediator'] },
    { 'feature-type': 'protocol', id: TRUST_PING, roles: ['receiver'] },
    { 'feature-type': 'protocol', id: DISCOVER_FEATURES, roles: ['responder'] },
    { 'feature-type': 'header', id: 'return_route' },
    { 'feature-type': 'constraint', id: MAX_RECEIVE_BYTES, [MAX_RECEIVE_BYTES]: String(maxReceiveBytes) },
  ]
}

/** A Discover Features `match`: a literal, or a pattern with `*` wildcards. */
function featureMatches(pattern: string, id: string): boolean {
  const source = pattern.split('*').map(part => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')
  return new RegExp(`^${source}$`).test(id)
}

/** One open WebSocket, as the transport (deployment.ts) hands it over. */
export interface LiveSocket {
  send(data: string): void
}

export interface MediatorHandler {
  /** Handles a mediator request, or returns null if the path isn't ours. */
  handle(req: Request, url: URL): Promise<Response | null>
  /** Resolves every did:webvh that holds an inbox again, so a device its DID
   * dropped loses its inbox now rather than at its next request. Does
   * nothing without `resolveWebvh`. */
  refreshWebvh(): Promise<{ checked: number; revoked: number }>
  /** The WebSocket transport: one call per text frame, and one when the
   * socket closes (live mode ends with the connection, Pickup 3.0). */
  live: {
    message(socket: LiveSocket, raw: string): Promise<void>
    close(socket: LiveSocket): void
  }
  mediatorDid: string
}

/** An authcrypt'd answer to `trigger`, to go back only if it asked. */
interface Reply { trigger: DidCommPlaintext; packed: string }
/** What one inbound message comes to: a reply message, or (for a Forward,
 * or anything not authenticated far enough to answer) a bare HTTP status. */
type Outcome = { reply: Reply } | { http: Response }

class Malformed extends Error {}
/** A did:webvh sender whose current keys do not include the key it used (or
 * whose log this mediator has not seen). */
class UnknownWebvhState extends Error {
  constructor(message: string, readonly code: string) { super(message) }
}

export function createMediator({
  mediator: mediatorOption, store, maxReceiveBytes = store.limits.maxMessageBytes, resolveWebvh,
  webvhFreshMs = 5 * 60_000, webvhRetryMs = 10_000, webvhStaleMs = 60 * 60_000, now = Date.now,
}: MediatorOptions): MediatorHandler {
  /** Per did:webvh: when it was last resolved successfully, and last tried. */
  const webvhChecks = new Map<string, { confirmedAt?: number; triedAt: number }>()
  const resolving = new Map<string, Promise<void>>()
  const mediator = 'peerKid' in mediatorOption ? mediatorOption : peerMediatorIdentity(mediatorOption)
  /** Every kid that names this mediator's key. A sender that took its key from
   * the did:web document uses that kid; one that took it from the did:peer
   * (a DID document published before, a relationship) uses the other. */
  const ownKids = new Set([mediator.xKid, ...mediator.aliasKids])
  const ownRecipientFor = (jwe: { recipients: Array<{ header: { kid: string } }> }) =>
    ({ kid: jwe.recipients.map(recipient => recipient.header.kid).find(kid => ownKids.has(kid)) ?? mediator.xKid, privateKey: mediator.xPriv })
  /** Per socket: the inboxes in live mode on it, each with its unsubscribe. */
  const liveInboxes = new WeakMap<LiveSocket, Map<string, () => void>>()

  /** The X25519 key of `kid` as this mediator holds it now -- self-certifying
   * for did:peer, the latest verified state for did:webvh. Throws for any kid
   * that is not (or is no longer) a keyAgreement key. */
  function heldKey(kid: string): Uint8Array {
    const did = didOf(kid)
    if (did.startsWith('did:webvh:')) {
      const hex = store.webvhKey(did, kid)
      if (!hex) {
        throw new UnknownWebvhState(
          `${kid} is not a keyAgreement key of ${did}`,
          resolveWebvh ? 'e.m.trust.sender-key-not-listed' : 'e.m.did.log-required',
        )
      }
      return fromHex(hex)
    }
    if (did.startsWith('did:peer:2.')) {
      const doc = decodePeerDid2(did)
      if (!doc.keyAgreement.includes(kid)) throw new Malformed(`${kid} is not a keyAgreement key of ${did}`)
      return publicKeyOf(doc, kid)
    }
    throw new Malformed(`unsupported DID method for ${kid}`)
  }

  /** Resolves `did` and records what it lists (revoking inboxes of keys it no
   * longer lists). One resolution at a time per DID. */
  function resolveAndRecord(did: string): Promise<void> {
    const running = resolving.get(did)
    if (running) return running
    const attempt = (async () => {
      const check = webvhChecks.get(did) ?? { triedAt: 0 }
      check.triedAt = now()
      webvhChecks.set(did, check)
      const state = await resolveWebvh!(did)
      if (state) {
        store.recordWebvhState(state.did, state.versionNumber, state.keys)
        check.confirmedAt = now()
      }
    })().finally(() => resolving.delete(did))
    resolving.set(did, attempt)
    return attempt
  }

  /** The X25519 key of `kid`. A did:webvh key is checked against a fresh
   * enough resolution of its DID first: a key just added is not in a state
   * held from before, so an unknown key triggers a resolve (no more often
   * than `webvhRetryMs`). */
  async function keyAgreementKey(kid: string): Promise<Uint8Array> {
    const did = didOf(kid)
    if (resolveWebvh && did.startsWith('did:webvh:')) {
      const check = webvhChecks.get(did)
      const listed = store.webvhKey(did, kid) !== undefined
      const fresh = check?.confirmedAt !== undefined && now() - check.confirmedAt < webvhFreshMs
      const recentlyTried = check !== undefined && now() - check.triedAt < webvhRetryMs
      if ((!listed || !fresh) && !recentlyTried) {
        try {
          await resolveAndRecord(did)
        } catch (error) {
          // The network failed. A state confirmed (or, for a pushed one,
          // recorded) recently enough still stands; otherwise ask to retry.
          const lastKnown = Math.max(check?.confirmedAt ?? 0, store.webvhStateRecordedAt(did) ?? 0)
          if (!listed || now() - lastKnown > webvhStaleMs) throw error instanceof WebvhUnavailable ? error : new WebvhUnavailable(error instanceof Error ? error.message : String(error))
        }
      }
    }
    return heldKey(kid)
  }

  async function refreshWebvh(): Promise<{ checked: number; revoked: number }> {
    if (!resolveWebvh) return { checked: 0, revoked: 0 }
    const dids = store.webvhRecipientDids()
    const before = store.stats().inboxes
    for (const did of dids) {
      try { await resolveAndRecord(did) } catch (error) { console.warn(`[mediator] could not re-check ${did}:`, error instanceof Error ? error.message : String(error)) }
    }
    return { checked: dids.length, revoked: Math.max(0, before - store.stats().inboxes) }
  }

  /** Authcrypts a reply back to the exact key that sent the request. */
  function packTo(plaintext: DidCommPlaintext, toKid: string): string {
    return JSON.stringify(packAuthcrypt(
      utf8(JSON.stringify(plaintext)),
      { kid: mediator.xKid, privateKey: mediator.xPriv },
      [{ kid: toKid, publicKey: heldKey(toKid) }],
    ))
  }

  function replyTo(trigger: DidCommPlaintext, senderKid: string, type: string, body: unknown, attachments?: DidCommPlaintext['attachments']): Outcome {
    const plaintext = buildPlaintext(type, body, mediator.did, didOf(senderKid), { thid: trigger.thid ?? trigger.id })
    if (attachments) plaintext.attachments = attachments
    return { reply: { trigger, packed: packTo(plaintext, senderKid) } }
  }

  /** A Report Problem 2.0 problem-report authcrypt'd back to the sender (in
   * DIDComm the response is itself a message; the failure is its `code`). */
  function problemTo(trigger: DidCommPlaintext, senderKid: string, code: string, comment: string, args?: string[]): Outcome {
    const ack = trigger.please_ack?.length ? [trigger.id] : undefined
    const report = buildProblemReport(mediator.did, didOf(senderKid), code, comment, { pthid: trigger.thid ?? trigger.id, ack }, args)
    return { reply: { trigger, packed: packTo(report, senderKid) } }
  }

  /** Queued copies for one inbox, as a Pickup 3.0 `delivery`. Each
   * attachment id is the mediator's own id for the body -- what the device
   * names back in messages-received. Pickup 3.0 carries each message as
   * `data.base64`: the encrypted message, base64url-encoded. */
  function deliveryAttachments(batch: QueuedMessage[]): NonNullable<DidCommPlaintext['attachments']> {
    return batch.map(m => ({ id: m.id, media_type: DIDCOMM_ENCRYPTED_MEDIA_TYPE, data: { base64: b64url(utf8(m.packed)) } }))
  }

  /** An error at the transport level (DIDComm transports: "it is also
   * appropriate to emit an error at the transport level, such as HTTP 413"),
   * with the standard problem-report as its body -- plaintext, since an error
   * for a sender nobody can name has nothing to encrypt to. `comment` is
   * fixed per `code`; what differs between occurrences is in `args`. With the
   * message that triggered it, the report refers to its thread (`pthid`) and
   * acknowledges it (`ack`); an unreadable request has no thread to refer to. */
  function httpProblem(status: number, code: string, comment: string, args: string[] = [], trigger?: DidCommPlaintext): Response {
    const report = buildPlaintext(PROBLEM_REPORT, { code, comment, ...(args.length ? { args } : {}) }, mediator.did, undefined, {
      lang: 'en', ...(trigger ? { pthid: trigger.thid ?? trigger.id, ack: [trigger.id] } : {}),
    })
    return new Response(JSON.stringify(report), { status, headers: { 'content-type': 'application/didcomm-plain+json' } })
  }

  /** A problem-report for an anoncrypt Forward, which has no sender to
   * encrypt an answer to: signed with this mediator's Ed25519 key, sent in
   * the clear, at 401 -- a Forward's sender reads only the HTTP status, and
   * anything 2xx would tell it the message was queued. */
  function signedProblem(trigger: DidCommPlaintext, toDid: string, code: string, comment: string, args?: string[]): Response {
    const report = buildProblemReport(mediator.did, didOf(toDid), code, comment, { pthid: trigger.thid ?? trigger.id }, args)
    const jws = packSigned(utf8(JSON.stringify(report)), { kid: mediator.edKid, edPrivateKey: mediator.edPriv })
    return new Response(JSON.stringify(jws), { status: 401, headers: { 'content-type': 'application/didcomm-signed+json' } })
  }

  /** Forward is anoncrypt by design (the mediator learns where to queue, not
   * who sent it); everything else is authcrypt'd and carries a verified
   * sender key. */
  async function unpack(raw: string): Promise<{ msg: DidCommPlaintext; senderKid: string | null }> {
    let body: unknown
    try { body = JSON.parse(raw) } catch { throw new Malformed('body is not JSON') }
    const jwe = parseJwe(body)
    if (!jwe) throw new Malformed('body is not a DIDComm JWE')
    const header = protectedHeaderOf(jwe)
    if (!header) throw new Malformed('the protected header is not readable')
    if (header.alg === 'ECDH-ES+A256KW') {
      const plaintext = await unpackAnoncrypt(jwe, ownRecipientFor(jwe))
      return { msg: JSON.parse(new TextDecoder().decode(plaintext)), senderKid: null }
    }
    const { plaintext, senderKid } = await unpackAuthcrypt(jwe, ownRecipientFor(jwe), kid => keyAgreementKey(kid))
    const msg = JSON.parse(new TextDecoder().decode(plaintext)) as DidCommPlaintext
    // Every rule below keys off the sender's DID, so `from` must be the DID
    // the envelope authenticated, not just a claim.
    try { assertFromMatchesSender(msg, senderKid) } catch (error) { throw new Malformed(error instanceof Error ? error.message : String(error)) }
    return { msg, senderKid }
  }

  /** `POST /webvh-log` -- a did:webvh log (JSONL), pushed by a client.
   * Not DIDComm (see webvh-state.ts): kept for a mediator that resolves
   * nothing. Self-certifying, so anyone may hand it over: it is verified in
   * full here and kept only if it is newer than what this mediator already
   * holds for that DID. */
  async function acceptWebvhLog(req: Request): Promise<Response> {
    let state: ReturnType<typeof webvhStateFromLog>
    try {
      state = webvhStateFromLog(await req.text())
    } catch (error) {
      return Response.json({ error: `not a valid did:webvh log: ${error instanceof Error ? error.message : String(error)}` }, { status: 400 })
    }
    const outcome = store.recordWebvhState(state.did, state.versionNumber, state.keys)
    return Response.json({ did: state.did, version: state.versionNumber, outcome })
  }

  async function handle(req: Request, url: URL): Promise<Response | null> {
    if (req.method === 'GET' && url.pathname === '/.well-known/did.json') return Response.json(mediator.doc)
    if (req.method === 'POST' && url.pathname === '/webvh-log') return acceptWebvhLog(req)
    if (url.pathname !== '/' || req.method !== 'POST') return null
    if (!isDidCommEncryptedRequest(req)) return httpProblem(415, 'e.m.msg', 'The request is not an encrypted DIDComm message: its Content-Type must be {1}.', [DIDCOMM_ENCRYPTED_MEDIA_TYPE])
    const outcome = await receive(await req.text())
    if ('http' in outcome) return outcome.http
    // No return_route: the answer has nowhere to go (the sender's own
    // endpoint is not ours to call), so the request is just accepted.
    if (outcome.reply.trigger.return_route !== 'all') return new Response(null, { status: 202 })
    return new Response(outcome.reply.packed, { status: 200, headers: { 'content-type': DIDCOMM_ENCRYPTED_MEDIA_TYPE } })
  }

  const live: MediatorHandler['live'] = {
    async message(socket, raw) {
      const outcome = await receive(raw, socket)
      if ('reply' in outcome && outcome.reply.trigger.return_route === 'all') socket.send(outcome.reply.packed)
    },
    close(socket) {
      for (const stop of liveInboxes.get(socket)?.values() ?? []) stop()
      liveInboxes.delete(socket)
    },
  }

  /** One inbound message from either transport. `socket` is set only for a
   * WebSocket -- the one transport live mode may be enabled on. */
  async function receive(raw: string, socket?: LiveSocket): Promise<Outcome> {
    let msg: DidCommPlaintext
    let senderKid: string | null
    try {
      ;({ msg, senderKid } = await unpack(raw))
    } catch (e) {
      if (e instanceof UnknownWebvhState) return { http: httpProblem(401, e.code, 'The sender could not be authenticated: {1}', [e.message]) }
      if (e instanceof WebvhUnavailable) return { http: httpProblem(503, 'e.m.me.res.net', "The sender's DID could not be resolved right now: {1}", [e.message]) }
      if (e instanceof Malformed) return { http: httpProblem(400, 'e.m.msg', 'The message is malformed: {1}', [e.message]) }
      console.error('[mediator] could not unpack an inbound message:', e)
      return { http: httpProblem(400, 'e.m.trust.crypto', 'The message could not be decrypted.') }
    }

    if (typeof msg.id !== 'string' || !msg.id) return { http: httpProblem(400, 'e.m.msg', 'The message has no `id`.') }
    if (msg.type !== FORWARD && !senderKid) {
      return { http: httpProblem(400, 'e.m.trust', 'This message type must be authcrypt\'d by an identified sender.', [], msg) }
    }
    if (isExpired(msg)) {
      return senderKid
        ? problemTo(msg, senderKid, 'e.m.req.time.expired', 'message expired (expires_time in the past)')
        : { http: httpProblem(400, 'e.m.req.time.expired', 'The message has expired.', [], msg) }
    }
    // Forward records its replay id in the same transaction as the queued
    // payload; everything else has no queue boundary and checks it here.
    if (msg.type !== FORWARD && !store.check(msg.id)) {
      return problemTo(msg, senderKid!, 'e.m.msg.duplicate', 'message id {1} has already been processed', [msg.id])
    }

    try {
      return msg.type === FORWARD ? { http: forward(msg) } : control(msg, senderKid!, socket)
    } catch (e) {
      console.error('[mediator] failed to handle a message:', e)
      return { http: httpProblem(500, 'e.m.me', 'The mediator failed to handle the message.', [], msg) }
    }
  }

  function forward(msg: DidCommPlaintext): Response {
    // Routing 2.0: `next` (a DID, or a key of it) in the body, the opaque
    // re-wrapped JWE as the single attachment. Never decrypted.
    const next = (msg.body as { next?: unknown } | undefined)?.next
    const forwarded = msg.attachments?.[0]?.data?.json
    if (typeof next !== 'string' || !next || forwarded === undefined) {
      return httpProblem(400, 'e.m.msg', 'A forward needs `next` and an attachment.', [], msg)
    }
    const did = didOf(next)
    let outcome: 'accepted' | 'not-enrolled' | 'replay'
    try {
      outcome = store.transaction(() => {
        if (!store.check(msg.id)) return 'replay'
        return store.enqueue(did, JSON.stringify(forwarded)) > 0 ? 'accepted' : 'not-enrolled'
      })
    } catch (e) {
      // The replay id rolls back with the failed insert, so the sender can
      // retry once an inbox drains. Never acknowledge an uncommitted body.
      if (e instanceof MessageTooBigError) return httpProblem(413, MESSAGE_TOO_BIG_PROBLEM, 'The message exceeds the limit of {1} bytes.', [String(store.limits.maxMessageBytes)], msg)
      if (e instanceof QueueFullError) return httpProblem(503, 'e.m.me.res.storage', 'Every inbox of the recipient is full.', [], msg)
      throw e
    }
    if (outcome === 'replay') {
      return httpProblem(400, 'e.m.msg.duplicate', 'Message id {1} has already been processed.', [msg.id], msg)
    }
    if (outcome === 'not-enrolled') return signedProblem(msg, next, 'e.m.req.not-enrolled', 'no device has registered {1}', [did])
    return new Response(null, { status: 202 })
  }

  /** Everything but Forward: an authenticated owner of `ownerDid` acting on
   * one of its own inboxes. */
  function control(msg: DidCommPlaintext, senderKid: string, socket?: LiveSocket): Outcome {
    const ownerDid = didOf(senderKid)
    const body = (msg.body ?? {}) as Record<string, unknown>

    switch (msg.type) {
      case PING:
        // Trust Ping 2.0: answer when asked (the default). With nothing
        // owed, the ping has done its job by arriving.
        return responseOwedFor(msg) ? replyTo(msg, senderKid, PING_RESPONSE, {}) : { http: new Response(null, { status: 202 }) }

      case DISCOVER_FEATURES_QUERIES: {
        const queries = Array.isArray(body.queries) ? body.queries as Array<{ 'feature-type'?: unknown; match?: unknown }> : []
        const disclosures = mediatorFeatures(maxReceiveBytes).filter(feature => queries.some(query =>
          query['feature-type'] === feature['feature-type'] && typeof query.match === 'string' && featureMatches(query.match, feature.id)))
        return replyTo(msg, senderKid, DISCOVER_FEATURES_DISCLOSE, { disclosures })
      }

      case MEDIATE_REQUEST:
        return replyTo(msg, senderKid, MEDIATE_GRANT, { routing_did: [mediator.did] })

      case RECIPIENT_QUERY: {
        // One entry per registered DID (Coordinate Mediation 3.0): the DID
        // this key owns, if it has any inbox here. `devices` -- one
        // `last_seen` per inbox -- is a biset extension: what a user needs to
        // see at the device limit. The inboxes' device labels are NOT listed:
        // anyone holding a DID's key may query, and a relationship did:peer's
        // key is shared by every device -- including one the identity later
        // removed, which could otherwise name a remaining device's inbox and
        // remove it. A label is unguessable (mediator-device.ts) unless listed.
        const inboxes = store.listInboxes(ownerDid)
        const all = inboxes.length > 0 ? [{ recipient_did: ownerDid, devices: inboxes.map(inbox => ({ last_seen: inbox.lastSeen })) }] : []
        const paginate = (body.paginate ?? {}) as { limit?: unknown; offset?: unknown }
        const offset = Number.isSafeInteger(paginate.offset) && (paginate.offset as number) > 0 ? paginate.offset as number : 0
        const limit = Number.isSafeInteger(paginate.limit) && (paginate.limit as number) > 0 ? paginate.limit as number : all.length
        const page = all.slice(offset, offset + limit)
        return replyTo(msg, senderKid, RECIPIENT, {
          dids: page,
          ...(body.paginate ? { pagination: { count: page.length, offset, remaining: Math.max(0, all.length - offset - page.length) } } : {}),
        })
      }

      case RECIPIENT_UPDATE: {
        const device = body.device === undefined ? defaultDeviceLabel(senderKid) : body.device
        if (!isDeviceLabel(device)) return problemTo(msg, senderKid, 'e.m.msg.invalid-device', 'the `device` label is not valid')
        const updates = Array.isArray(body.updates) ? body.updates as Array<{ recipient_did?: unknown; action?: unknown }> : []
        const updated: Array<{ recipient_did: unknown; action: unknown; result: string }> = []
        for (const update of updates) {
          // Ownership: the key that sent this must belong to the DID it
          // registers. A request can only ever touch its own DID.
          if (typeof update.recipient_did !== 'string' || didOf(update.recipient_did) !== ownerDid || (update.action !== 'add' && update.action !== 'remove')) {
            updated.push({ recipient_did: update.recipient_did, action: update.action, result: 'client_error' })
            continue
          }
          if (update.action === 'remove') {
            updated.push({ recipient_did: update.recipient_did, action: 'remove', result: store.removeInbox(ownerDid, device) ? 'success' : 'no_change' })
            continue
          }
          try {
            const result = store.addInbox(ownerDid, device, senderKid)
            updated.push({ recipient_did: update.recipient_did, action: 'add', result: result === 'unchanged' ? 'no_change' : 'success' })
          } catch (e) {
            if (e instanceof TooManyDevicesError) {
              return problemTo(msg, senderKid, MAX_DEVICES_PROBLEM, '{1} already has {2} devices registered at this mediator (limit {3})', [ownerDid, String(e.devices.length), String(e.limit)])
            }
            if (e instanceof MediatorFullError) return problemTo(msg, senderKid, 'e.m.me.res.storage', 'mediator is at capacity')
            throw e
          }
        }
        return replyTo(msg, senderKid, RECIPIENT_UPDATE_RESPONSE, { updated })
      }
    }

    // Pickup family: one named inbox of the sender's own DID.
    const device = body.device === undefined ? defaultDeviceLabel(senderKid) : body.device
    const asked = body.recipient_did
    if (!isDeviceLabel(device) || (asked !== undefined && (typeof asked !== 'string' || didOf(asked) !== ownerDid)) || !store.hasInbox(ownerDid, device)) {
      return problemTo(msg, senderKid, 'e.m.req.not-enrolled', 'no inbox {2} is registered for {1}', [ownerDid, String(device)])
    }
    store.touch(ownerDid, device)
    const liveKey = `${ownerDid}\n${device}`
    // Pickup 3.0: every status says whether live delivery is on -- only ever
    // true on a WebSocket where this inbox switched it on.
    const status = () => {
      const missed = store.takeMissed(ownerDid, device)
      return {
        recipient_did: ownerDid, message_count: store.count(ownerDid, device),
        live_delivery: socket !== undefined && liveInboxes.get(socket)?.has(liveKey) === true,
        ...(missed ? { missed: true } : {}),
      }
    }

    switch (msg.type) {
      case STATUS_REQUEST:
        return replyTo(msg, senderKid, STATUS, status())

      case LIVE_DELIVERY_CHANGE: {
        // Pushing needs a connection to push on, and the device's consent to
        // receive on it (return_route) -- Pickup 3.0 live mode.
        if (!socket || msg.return_route !== 'all') {
          return problemTo(msg, senderKid, LIVE_MODE_NOT_SUPPORTED_PROBLEM, 'live delivery needs a WebSocket and return_route "all"')
        }
        const inboxes = liveInboxes.get(socket) ?? new Map<string, () => void>()
        liveInboxes.set(socket, inboxes)
        const key = `${ownerDid}\n${device}`
        inboxes.get(key)?.()
        inboxes.delete(key)
        if (body.live_delivery === true) {
          const stop = store.subscribe(ownerDid, device, messages => {
            try {
              const plaintext = buildPlaintext(DELIVERY, { recipient_did: ownerDid }, mediator.did, ownerDid, { attachments: deliveryAttachments(messages) })
              socket.send(packTo(plaintext, senderKid))
            } catch {
              // The key that enabled live mode is gone (a newer log dropped
              // it): stop pushing. The copies stay queued.
              stop()
              inboxes.delete(key)
            }
          })
          inboxes.set(key, stop)
        }
        return replyTo(msg, senderKid, STATUS, status())
      }

      case DELIVERY_REQUEST: {
        const requested = Number(body.limit ?? 10)
        const limit = Number.isFinite(requested) ? Math.max(1, Math.min(Math.trunc(requested), 100)) : 10
        const batch = store.peek(ownerDid, device, limit)
        if (batch.length === 0) return replyTo(msg, senderKid, STATUS, status())
        // `recipient_did` only when the request named one (Pickup 3.0).
        return replyTo(msg, senderKid, DELIVERY, asked === undefined ? {} : { recipient_did: ownerDid }, deliveryAttachments(batch))
      }

      case MESSAGES_RECEIVED: {
        const ids = Array.isArray(body.message_id_list) ? body.message_id_list.filter((id): id is string => typeof id === 'string') : []
        store.acknowledge(ownerDid, device, ids)
        return replyTo(msg, senderKid, STATUS, status())
      }

      default:
        return problemTo(msg, senderKid, 'e.m.msg.not-recognized', 'unrecognized message type {1}', [msg.type])
    }
  }

  return { handle, live, mediatorDid: mediator.did, refreshWebvh }
}

