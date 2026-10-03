// The DIDComm v2 mediator: Coordinate Mediation 2.0, Routing 2.0, Pickup 3.0.
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
// Registering recipient DID X (keylist-update add) is allowed exactly when
// that key is one of X's own keyAgreement keys -- holding X's private key IS
// the proof of owning X. Coordinate Mediation 2.0/3.0 leave this check out
// (3.0 names it under "Future Considerations"); without it anyone could
// register someone else's public DID here and collect copies of their
// traffic or block their registration.
//
// Ownership says nothing about WHICH of X's devices is asking, and a
// relationship did:peer shares one key across all of them, so each request
// also names its inbox with a `device` label (a biset extension field):
// one inbox per (X, device), at most `maxDevicesPerDid` per X. A Forward for
// X is copied into every live inbox of X (routing.md lets a mediator
// multiplex to a recipient's several physical devices).
//
// did:peer keys are read straight out of the DID. did:webvh keys come from
// the latest log a client pushed to `POST /webvh-log` -- verified here, no
// network, and a newer log revokes every inbox registered with a key it no
// longer lists.
import { decodePeerDid2, publicKeyOf, type PeerIdentity } from '../../protocol/didcomm/peer.ts'
import { assertFromMatchesSender, buildPlaintext, isExpired, type DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { buildProblemReport } from '../../protocol/didcomm/problems.ts'
import {
  packAuthcrypt, unpackAuthcrypt, unpackAnoncrypt, parseJwe, protectedHeaderOf,
  DIDCOMM_ENCRYPTED_MEDIA_TYPE, isDidCommEncryptedRequest,
} from '../../protocol/didcomm/crypto.ts'
import { decodeX25519Multikey } from '../../protocol/didcomm/multikey.ts'
import { parseLog, entryVersionNumber } from '../../protocol/webvh/log.ts'
import { resolveEntries } from '../../protocol/webvh/resolver.ts'
import type { WebvhDidDocument } from '../../protocol/webvh/document.ts'
import { packSigned } from './signature.ts'
import { PING, PING_RESPONSE, responseOwedFor } from '../../protocol/didcomm/trust-ping.ts'
import {
  isDeviceLabel, MediatorFullError, QueueFullError, TooManyDevicesError,
  type QueuedMessage, type SqliteMediatorStore,
} from './sqlite-store.ts'
import {
  MEDIATE_REQUEST, MEDIATE_GRANT, KEYLIST_UPDATE, KEYLIST_UPDATE_RESPONSE, KEYLIST_QUERY, KEYLIST,
  FORWARD, STATUS_REQUEST, STATUS, DELIVERY_REQUEST, DELIVERY, MESSAGES_RECEIVED,
  LIVE_DELIVERY_CHANGE, LIVE_MODE_NOT_SUPPORTED_PROBLEM, MAX_DEVICES_PROBLEM,
} from '../../protocol/didcomm/mediator-protocol.ts'

function didOf(didOrKidUrl: string): string {
  const i = didOrKidUrl.indexOf('#')
  return i === -1 ? didOrKidUrl : didOrKidUrl.slice(0, i)
}

const utf8 = (s: string) => new TextEncoder().encode(s)
const toHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')
const fromHex = (h: string): Uint8Array => new Uint8Array((h.match(/../g) ?? []).map(x => parseInt(x, 16)))

/** Every keyAgreement kid (absolute) of a resolved did:webvh document and
 * its X25519 key, hex. Entries this mediator can't read are left out --
 * they can't authenticate anything here anyway. */
function webvhKeyAgreementKeys(doc: WebvhDidDocument): Record<string, string> {
  const absolute = (id: string) => id.startsWith('#') ? `${doc.id}${id}` : id
  const keys: Record<string, string> = {}
  for (const ref of doc.keyAgreement ?? []) {
    const kid = absolute(ref)
    const method = doc.verificationMethod.find(vm => absolute(vm.id) === kid)
    if (!method) continue
    try { keys[kid] = toHex(decodeX25519Multikey(method.publicKeyMultibase)) } catch { /* not X25519 */ }
  }
  return keys
}

export interface MediatorOptions {
  mediator: PeerIdentity
  store: SqliteMediatorStore
}

/** One open WebSocket, as the transport (deployment.ts) hands it over. */
export interface LiveSocket {
  send(data: string): void
}

export interface MediatorHandler {
  /** Handles a mediator request, or returns null if the path isn't ours. */
  handle(req: Request, url: URL): Promise<Response | null>
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
/** A did:webvh sender whose log this mediator has not been given yet. */
class UnknownWebvhState extends Error {}

export function createMediator({ mediator, store }: MediatorOptions): MediatorHandler {
  const ownRecipient = { kid: mediator.xKid, privateKey: mediator.xPriv }
  /** Per socket: the inboxes in live mode on it, each with its unsubscribe. */
  const liveInboxes = new WeakMap<LiveSocket, Map<string, () => void>>()

  /** The X25519 key of `kid`, a keyAgreement key of the DID it names --
   * self-certifying for did:peer, the latest pushed log for did:webvh.
   * Throws for any kid that is not (or is no longer) such a key. */
  function keyAgreementKey(kid: string): Uint8Array {
    const did = didOf(kid)
    if (did.startsWith('did:webvh:')) {
      const hex = store.webvhKey(did, kid)
      if (!hex) throw new UnknownWebvhState(`${kid} is not a keyAgreement key of the latest ${did} log this mediator holds`)
      return fromHex(hex)
    }
    if (did.startsWith('did:peer:2.')) {
      const doc = decodePeerDid2(did)
      if (!doc.keyAgreement.includes(kid)) throw new Malformed(`${kid} is not a keyAgreement key of ${did}`)
      return publicKeyOf(doc, kid)
    }
    throw new Malformed(`unsupported DID method for ${kid}`)
  }

  /** Authcrypts a reply back to the exact key that sent the request. */
  function packTo(plaintext: DidCommPlaintext, toKid: string): string {
    return JSON.stringify(packAuthcrypt(
      utf8(JSON.stringify(plaintext)),
      { kid: mediator.xKid, privateKey: mediator.xPriv },
      [{ kid: toKid, publicKey: keyAgreementKey(toKid) }],
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
   * names back in messages-received. */
  function deliveryAttachments(batch: QueuedMessage[]): NonNullable<DidCommPlaintext['attachments']> {
    return batch.map(m => ({ id: m.id, data: { json: JSON.parse(m.packed) } }))
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
      const plaintext = await unpackAnoncrypt(jwe, ownRecipient)
      return { msg: JSON.parse(new TextDecoder().decode(plaintext)), senderKid: null }
    }
    const { plaintext, senderKid } = await unpackAuthcrypt(jwe, ownRecipient, async kid => keyAgreementKey(kid))
    const msg = JSON.parse(new TextDecoder().decode(plaintext)) as DidCommPlaintext
    // Every rule below keys off the sender's DID, so `from` must be the DID
    // the envelope authenticated, not just a claim.
    try { assertFromMatchesSender(msg, senderKid) } catch (error) { throw new Malformed(error instanceof Error ? error.message : String(error)) }
    return { msg, senderKid }
  }

  /** `POST /webvh-log` -- a did:webvh log (JSONL). Self-certifying, so
   * anyone may hand it over: it is verified in full here and kept only if
   * it is newer than what this mediator already holds for that DID. */
  async function acceptWebvhLog(req: Request): Promise<Response> {
    let doc: WebvhDidDocument | null
    let versionNumber: number
    try {
      const entries = parseLog(await req.text())
      const did = (entries[0]?.state as { id?: unknown } | undefined)?.id
      if (typeof did !== 'string' || !did.startsWith('did:webvh:')) throw new Error('the log does not name a did:webvh')
      doc = resolveEntries(did, entries)
      if (!doc || doc.id !== did) throw new Error('the log does not resolve to its own DID')
      versionNumber = entryVersionNumber(entries[entries.length - 1]!.versionId)
    } catch (error) {
      return Response.json({ error: `not a valid did:webvh log: ${error instanceof Error ? error.message : String(error)}` }, { status: 400 })
    }
    const outcome = store.recordWebvhState(doc.id, versionNumber, webvhKeyAgreementKeys(doc))
    return Response.json({ did: doc.id, version: versionNumber, outcome })
  }

  async function handle(req: Request, url: URL): Promise<Response | null> {
    if (req.method === 'GET' && url.pathname === '/.well-known/did.json') return Response.json(mediator.doc)
    if (req.method === 'POST' && url.pathname === '/webvh-log') return acceptWebvhLog(req)
    if (url.pathname !== '/' || req.method !== 'POST') return null
    if (!isDidCommEncryptedRequest(req)) return Response.json({ error: `Content-Type must be ${DIDCOMM_ENCRYPTED_MEDIA_TYPE}` }, { status: 415 })
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
      if (e instanceof UnknownWebvhState) return { http: Response.json({ error: e.message, code: 'e.p.req.webvh-log-required' }, { status: 401 }) }
      if (e instanceof Malformed) return { http: Response.json({ error: e.message }, { status: 400 }) }
      console.error('[mediator] could not unpack an inbound message:', e)
      return { http: Response.json({ error: 'could not read this message' }, { status: 400 }) }
    }

    if (typeof msg.id !== 'string' || !msg.id) return { http: Response.json({ error: 'message has no `id`' }, { status: 400 }) }
    if (msg.type !== FORWARD && !senderKid) {
      return { http: Response.json({ error: 'this message type requires an authcrypt sender' }, { status: 400 }) }
    }
    if (isExpired(msg)) {
      return senderKid
        ? problemTo(msg, senderKid, 'e.p.msg.expired', 'message expired (expires_time in the past)')
        : { http: Response.json({ error: 'message expired' }, { status: 400 }) }
    }
    // Forward records its replay id in the same transaction as the queued
    // payload; everything else has no queue boundary and checks it here.
    if (msg.type !== FORWARD && !store.check(msg.id)) {
      return problemTo(msg, senderKid!, 'e.p.crypto.message.dejavu', 'message id {1} has already been processed', [msg.id])
    }

    try {
      return msg.type === FORWARD ? { http: forward(msg) } : control(msg, senderKid!, socket)
    } catch (e) {
      return { http: Response.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 }) }
    }
  }

  function forward(msg: DidCommPlaintext): Response {
    // Routing 2.0: `next` (a DID, or a key of it) in the body, the opaque
    // re-wrapped JWE as the single attachment. Never decrypted.
    const next = (msg.body as { next?: unknown } | undefined)?.next
    const forwarded = msg.attachments?.[0]?.data?.json
    if (typeof next !== 'string' || !next || forwarded === undefined) {
      return Response.json({ error: 'forward is missing `next` or its attachment' }, { status: 400 })
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
      if (e instanceof QueueFullError) return Response.json({ error: e.message }, { status: 503 })
      throw e
    }
    if (outcome === 'replay') {
      return Response.json({ error: `message id ${msg.id} has already been processed`, code: 'e.p.crypto.message.dejavu' }, { status: 400 })
    }
    if (outcome === 'not-enrolled') return signedProblem(msg, next, 'e.p.req.not_enroll', 'no device has registered {1}', [did])
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

      case MEDIATE_REQUEST:
        return replyTo(msg, senderKid, MEDIATE_GRANT, { routing_did: mediator.did })

      case KEYLIST_QUERY:
        return replyTo(msg, senderKid, KEYLIST, {
          keys: store.listInboxes(ownerDid).map(inbox => ({ recipient_did: ownerDid, device: inbox.device, last_seen: inbox.lastSeen })),
        })

      case KEYLIST_UPDATE: {
        const device = body.device
        if (!isDeviceLabel(device)) return problemTo(msg, senderKid, 'e.p.msg.invalid-device', 'keylist-update needs a `device` label')
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
            if (e instanceof MediatorFullError) return problemTo(msg, senderKid, 'e.p.me.res.storage', 'mediator is at capacity')
            throw e
          }
        }
        return replyTo(msg, senderKid, KEYLIST_UPDATE_RESPONSE, { updated })
      }
    }

    // Pickup family: one named inbox of the sender's own DID.
    const device = body.device
    const asked = body.recipient_did
    if (!isDeviceLabel(device) || (asked !== undefined && (typeof asked !== 'string' || didOf(asked) !== ownerDid)) || !store.hasInbox(ownerDid, device)) {
      return problemTo(msg, senderKid, 'e.p.req.not_enroll', 'no inbox {2} is registered for {1}', [ownerDid, String(device)])
    }
    store.touch(ownerDid, device)
    const status = () => {
      const missed = store.takeMissed(ownerDid, device)
      return { recipient_did: ownerDid, message_count: store.count(ownerDid, device), ...(missed ? { missed: true } : {}) }
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
              const plaintext = buildPlaintext(DELIVERY, { recipient_did: ownerDid, device }, mediator.did, ownerDid, { attachments: deliveryAttachments(messages) })
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
        return replyTo(msg, senderKid, STATUS, { ...status(), live_delivery: inboxes.has(key) })
      }

      case DELIVERY_REQUEST: {
        const asked = Number(body.limit ?? 10)
        const limit = Number.isFinite(asked) ? Math.max(1, Math.min(Math.trunc(asked), 100)) : 10
        const batch = store.peek(ownerDid, device, limit)
        if (batch.length === 0) return replyTo(msg, senderKid, STATUS, status())
        return replyTo(msg, senderKid, DELIVERY, { recipient_did: ownerDid, device }, deliveryAttachments(batch))
      }

      case MESSAGES_RECEIVED: {
        const ids = Array.isArray(body.message_id_list) ? body.message_id_list.filter((id): id is string => typeof id === 'string') : []
        store.acknowledge(ownerDid, device, ids)
        return replyTo(msg, senderKid, STATUS, status())
      }

      default:
        return problemTo(msg, senderKid, 'e.p.msg.not-recognized', 'unrecognized message type {1}', [msg.type])
    }
  }

  return { handle, live, mediatorDid: mediator.did }
}

