// The DIDComm v2 mediator: Coordinate Mediation 2.0, Routing 2.0, Pickup 3.0.
// A client that can't hold a socket open (a browser) registers here, gives the
// mediator's URL out as its own DIDComm endpoint, and collects what arrives
// whenever it's next running.
//
// **This speaks biset's own DIDComm implementation (`src/did/didcomm/`), not a
// library.** It previously used `didcomm-node`, which loads its Rust core from
// a `.wasm` file it reads off disk at runtime (`readFileSync(__dirname +
// '/index_bg.wasm')`) — so `bun build --compile` cannot fold it into a
// standalone binary, and the anchor's "one artifact, no runtime dependencies"
// property could not survive absorbing it. Using our own is not a compromise
// forced by that: the client already had to implement pack/unpack to run in a
// browser, both sides of every message here are ours, and one implementation is
// the whole reason the mediator moved into this repo.
import { decodePeerDid2, type PeerIdentity, type PeerDidDoc } from '../../did/peer.ts'
import { buildPlaintext, publicKeyOf, isExpired, type DidCommPlaintext } from '../../did/didcomm/message.ts'
import { packAuthcrypt, unpackAuthcrypt, unpackAnoncrypt, b64urlToBytes, type DidCommJWE } from '../../did/didcomm/crypto.ts'
import { SeenIds } from '../../did/didcomm/replay.ts'
import { MessageQueue, QueueFullError } from './queue.ts'
import { ConnectionStore, ConnectionFullError } from './connections.ts'

const MEDIATE_REQUEST = 'https://didcomm.org/coordinate-mediation/2.0/mediate-request'
const MEDIATE_GRANT = 'https://didcomm.org/coordinate-mediation/2.0/mediate-grant'
const KEYLIST_UPDATE = 'https://didcomm.org/coordinate-mediation/2.0/keylist-update'
const KEYLIST_UPDATE_RESPONSE = 'https://didcomm.org/coordinate-mediation/2.0/keylist-update-response'
const KEYLIST_QUERY = 'https://didcomm.org/coordinate-mediation/2.0/keylist-query'
const KEYLIST = 'https://didcomm.org/coordinate-mediation/2.0/keylist'
const FORWARD = 'https://didcomm.org/routing/2.0/forward'
const STATUS_REQUEST = 'https://didcomm.org/messagepickup/3.0/status-request'
const STATUS = 'https://didcomm.org/messagepickup/3.0/status'
const DELIVERY_REQUEST = 'https://didcomm.org/messagepickup/3.0/delivery-request'
const DELIVERY = 'https://didcomm.org/messagepickup/3.0/delivery'

const DIDCOMM_CT = 'application/didcomm-encrypted+json'

function stripFragment(didOrKidUrl: string): string {
  const i = didOrKidUrl.indexOf('#')
  return i === -1 ? didOrKidUrl : didOrKidUrl.slice(0, i)
}

/** Forward's `next`, keylist registrations and Pickup's `recipient_did` must
 * all agree on one KID (not just DID) for multi-device delivery to route to
 * the right device's queue (document.ts's DidKeyAgreement note — one kid per
 * device). A bare DID (no fragment) defaults to that identity's PRIMARY
 * device (#k1), for callers that predate multi-device or hold only one; a
 * full kid URL passes through unchanged.
 *
 * This used to collapse everything to the bare DID — fine when there was only
 * ever one possible kid, but it silently pooled every device's Forward/queue
 * traffic into one shared bucket once there could be more than one: whichever
 * device polled DELIVERY_REQUEST first drained messages addressed to every
 * OTHER device too, the rest getting nothing. Keeping the kid distinct is the
 * actual fix multi-device delivery needed — the keyAgreementKeys/fan-out work
 * elsewhere only supplies multiple ADDRESSES; this is what keeps them from
 * being routed into the same box regardless. */
function normalizeKid(didOrKidUrl: string): string {
  return didOrKidUrl.includes('#') ? didOrKidUrl : `${didOrKidUrl}#k1`
}

/** did:peer:2 is self-certifying — the keys are *in* the DID string, so every
 * resolution here is a decode, never a network call. That is exactly why the
 * mediator can be strict about senders without needing a DHT gateway. */
function docFor(did: string): PeerDidDoc {
  return decodePeerDid2(did)
}

function xKidOf(doc: PeerDidDoc): string {
  const kid = doc.keyAgreement[0]
  if (!kid) throw new Error(`${doc.id} has no keyAgreement key`)
  return kid
}

const utf8 = (s: string) => new TextEncoder().encode(s)

export interface MediatorOptions {
  mediator: PeerIdentity
  queue?: MessageQueue
  connections?: ConnectionStore
  /** Resolve a `did:dht` peer's DIDComm key (x25519) at a SPECIFIC kid — needed
   * to authenticate senders and encrypt replies that identify by did:dht
   * rather than the self-certifying did:peer. Kid-aware because a relay-less
   * identity (DID⊥relay) can have more than one registered device, each at
   * its own kid (document.ts's DidKeyAgreement note) — resolving "the" key for
   * a bare DID would pick an arbitrary one. Without this option the mediator
   * handles did:peer only (the original assumption). The anchor supplies one
   * backed by its DHT access; a mediator run standalone may omit it. */
  resolveDidDht?: (did: string, kid: string) => Promise<Uint8Array | null>
}

export interface MediatorHandler {
  /** Handles a mediator request, or returns null if the path isn't ours. */
  handle(req: Request, url: URL): Promise<Response | null>
  mediatorDid: string
}

export function createMediator({ mediator, queue = new MessageQueue(), connections = new ConnectionStore(), resolveDidDht }: MediatorOptions): MediatorHandler {
  const ownRecipient = { kid: mediator.xKid, privateKey: mediator.xPriv }
  // Replay guard over every inbound message's `id` — a re-POSTed anoncrypt
  // Forward would otherwise re-queue the same payload, and a resent authcrypt
  // request would be re-processed (a replayed DELIVERY_REQUEST re-drains a
  // queue). Bounded + TTL'd so it can't itself be turned into a memory DoS.
  const seen = new SeenIds()

  /** The x25519 key + its kid for a peer identified by either method, AT A
   * SPECIFIC device's kid. did:peer is self-certifying and has exactly one
   * key regardless of what `kid` names (decode, no network — the passed kid
   * is ignored, always resolved canonically, and by construction always
   * matches anyway: every did:peer identity in this codebase mints exactly
   * one x25519 key). did:dht is resolved from the DHT via the injected
   * resolver, AT `kid` specifically — a relay-less identity (DID⊥relay) can
   * have multiple registered devices, and this is what picks the right one
   * instead of an arbitrary "the" key. */
  async function didCommKey(did: string, kid: string): Promise<{ xKid: string; publicKey: Uint8Array }> {
    if (did.startsWith('did:dht:')) {
      if (!resolveDidDht) throw new Error(`no did:dht resolver configured for ${kid}`)
      const key = await resolveDidDht(did, kid)
      if (!key) throw new Error(`unresolvable did:dht peer ${kid} (no such key on the DHT / no resolver)`)
      return { xKid: kid, publicKey: key }
    }
    const doc = docFor(did)
    const canonicalKid = xKidOf(doc)
    return { xKid: canonicalKid, publicKey: publicKeyOf(doc, canonicalKid) }
  }

  /** The sender's key, at the exact kid it claimed (authcrypt's own `skid`
   * header, not `msg.from` — a bare DID that never carries which device sent
   * it). For did:peer it comes out of the DID string itself, so a forged
   * `skid` cannot name a key the sender doesn't hold — authcrypt then fails to
   * decrypt, which is the authentication. For did:dht the same holds once the
   * claimed device's key is resolved from the (signed) DHT document. */
  async function resolveSenderKey(senderKid: string): Promise<Uint8Array> {
    const did = stripFragment(senderKid)
    return (await didCommKey(did, senderKid)).publicKey
  }

  /** Replies to `toKid` SPECIFICALLY — the exact device that authenticated the
   * request being answered (handle()'s replyKid), not just any of the
   * sender's registered devices; otherwise a reply to a multi-device identity
   * could land encrypted to a key a different device holds. */
  async function packReplyTo(
    toDid: string, toKid: string, type: string, body: unknown,
    attachments?: DidCommPlaintext['attachments'],
    // Pre-resolved key, when the caller already needed to resolve it BEFORE
    // a destructive step (DELIVERY_REQUEST's queue.take() below) and can't
    // afford this function's own resolve to be the one that fails after the
    // fact. Defaults to resolving here, unchanged for every other caller.
    resolvedKey?: { xKid: string; publicKey: Uint8Array },
  ): Promise<string> {
    const plaintext = buildPlaintext(type, body, mediator.did, toDid)
    if (attachments) plaintext.attachments = attachments
    const { xKid, publicKey } = resolvedKey ?? await didCommKey(toDid, toKid)
    const jwe = packAuthcrypt(
      utf8(JSON.stringify(plaintext)),
      { kid: mediator.xKid, privateKey: mediator.xPriv },
      { kid: xKid, publicKey },
    )
    return JSON.stringify(jwe)
  }

  const reply = (packed: string) => new Response(packed, { status: 200, headers: { 'content-type': DIDCOMM_CT } })

  /** Unpacks either flavour. The `alg` header decides: Forward is anoncrypt by
   * design — the whole point of routing is that the mediator learns where to
   * queue, not who sent it — while everything else is authcrypt'd and carries
   * a verified sender. */
  async function unpack(raw: string): Promise<{ msg: DidCommPlaintext; senderKid: string | null }> {
    const jwe = JSON.parse(raw) as DidCommJWE
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
    if (header.alg === 'ECDH-ES+A256KW') {
      const plaintext = await unpackAnoncrypt(jwe, ownRecipient)
      return { msg: JSON.parse(new TextDecoder().decode(plaintext)), senderKid: null }
    }
    const { plaintext, senderKid } = await unpackAuthcrypt(jwe, ownRecipient, resolveSenderKey)
    return { msg: JSON.parse(new TextDecoder().decode(plaintext)), senderKid }
  }

  async function handle(req: Request, url: URL): Promise<Response | null> {
    if (req.method === 'GET' && url.pathname === '/.well-known/did.json') {
      return Response.json(mediator.doc)
    }
    if (url.pathname !== '/' || req.method !== 'POST') return null

    let msg: DidCommPlaintext
    let senderKid: string | null
    try {
      ;({ msg, senderKid } = await unpack(await req.text()))
    } catch (e) {
      return Response.json({ error: String(e) }, { status: 400 })
    }

    // Every plaintext MUST carry an `id` (threading.md: a message without one
    // SHOULD be rejected and MUST NOT be treated as part of an interaction).
    if (typeof msg.id !== 'string' || !msg.id) {
      return Response.json({ error: 'message has no `id`' }, { status: 400 })
    }
    // A message past its own `expires_time` is stale by the sender's own
    // declaration — don't queue or act on it (problems.md "Timeouts").
    if (isExpired(msg)) {
      return Response.json({ error: 'message expired (expires_time in the past)' }, { status: 400 })
    }
    // Replay: a second live arrival of the same id is a resend of a message we
    // already handled. Checked AFTER expiry so a stale replay is reported as
    // expired (the more actionable cause) rather than as a duplicate.
    if (!seen.check(msg.id)) {
      return Response.json({ error: 'replayed message id' }, { status: 400 })
    }

    // `from` is the sender's own claim, but authcrypt already proved they hold
    // that DID's key (resolveSenderKey above), so it is safe to trust here.
    const fromDid: string | undefined = msg.from
    if (msg.type !== FORWARD && !fromDid) {
      return Response.json({ error: 'message has no `from` — this message type requires an authenticated sender' }, { status: 400 })
    }
    // Replies go to the EXACT device that authenticated this request
    // (senderKid, authcrypt's own `skid` — `msg.from` is always a bare DID,
    // never naming which device sent it, see normalizeKid's note). FORWARD is
    // anoncrypt (no senderKid) but never replies, so this fallback is
    // defensive only.
    const replyKid = senderKid ?? (fromDid ? `${fromDid}#k1` : undefined)

    // Defense in depth around the whole dispatch, on top of DELIVERY_REQUEST's
    // own queue-ordering fix above: found live, an unhandled exception here
    // (any case's packReplyTo hitting a did:dht resolve hiccup) showed up in
    // the anchor's own logs as an uncaught rejection, and the process was
    // observed restarting periodically around the same errors — every
    // in-memory queued message lost on restart (queue.ts's own note: volatile
    // by design). One request that can't be answered must 500, not take the
    // whole mediator down with it.
    try {
      return await dispatch(msg, fromDid, replyKid)
    } catch (e) {
      return Response.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 })
    }
  }

  async function dispatch(msg: DidCommPlaintext, fromDid: string | undefined, replyKid: string | undefined): Promise<Response> {
    switch (msg.type) {
      case MEDIATE_REQUEST: {
        try {
          connections.register(fromDid!)
        } catch (e) {
          if (e instanceof ConnectionFullError) return Response.json({ error: String(e.message) }, { status: 503 })
          throw e
        }
        return reply(await packReplyTo(fromDid!, replyKid!, MEDIATE_GRANT, { routing_did: mediator.did }))
      }

      case KEYLIST_UPDATE: {
        const updates: Array<{ recipient_did: string; action: 'add' | 'remove' }> = (msg.body as any)?.updates ?? []
        // Per-update result, as Coordinate Mediation 2.0 defines it: one refused
        // key reports itself and the rest still land, rather than the whole
        // batch failing over the last one.
        const updated = updates.map(u => {
          const kid = normalizeKid(u.recipient_did)
          try {
            if (u.action === 'add') connections.addKey(fromDid!, kid)
            else connections.removeKey(fromDid!, kid)
          } catch (e) {
            if (e instanceof ConnectionFullError) {
              return { recipient_did: u.recipient_did, action: u.action, result: 'server_error' }
            }
            throw e
          }
          return { recipient_did: u.recipient_did, action: u.action, result: 'success' }
        })
        return reply(await packReplyTo(fromDid!, replyKid!, KEYLIST_UPDATE_RESPONSE, { updated }))
      }

      case KEYLIST_QUERY: {
        // Coordinate Mediation 2.0 keylist-query → keylist. Returns the kids
        // THIS authenticated client (fromDid = the identity's shared DID
        // across all its devices) currently has registered — the
        // authoritative live-device set. A client republishing its DID
        // document uses this to drop any keyAgreementKey the mediator no
        // longer lists (a logged-out sibling), overriding its own stale
        // sibling cache so a removal actually converges instead of being
        // resurrected by whichever device last republished from a pre-logout
        // snapshot. Authenticated by construction: fromDid comes from the
        // authcrypt envelope, so a client can only ever read its own keylist.
        const keys = connections.listKeys(fromDid!)
        return reply(await packReplyTo(fromDid!, replyKid!, KEYLIST, {
          keys: keys.map(k => ({ recipient_did: k })),
        }))
      }

      case FORWARD: {
        // Routing 2.0's shape, which biset's own send.ts builds: `next` in the
        // body, the opaque re-wrapped JWE as the single attachment. We never
        // decrypt that inner message — we can't, and that's the point.
        const next = (msg.body as any)?.next
        const forwarded = msg.attachments?.[0]?.data?.json
        if (!next || forwarded === undefined) {
          return Response.json({ error: 'forward is missing `next` or its attachment' }, { status: 400 })
        }
        const kid = normalizeKid(next)
        if (!connections.isAuthorized(kid)) {
          return Response.json({ error: 'uncoordinated recipient — no keylist-update registered this kid' }, { status: 401 })
        }
        try {
          queue.push(kid, JSON.stringify(forwarded))
        } catch (e) {
          // 503, not a silent drop: the sender is the only party who can still
          // do something about it (retry, or route another way), and this is the
          // last point that knows the message existed.
          if (e instanceof QueueFullError) return Response.json({ error: String(e.message) }, { status: 503 })
          throw e
        }
        return new Response(null, { status: 202 })
      }

      case STATUS_REQUEST: {
        const kid = normalizeKid((msg.body as any)?.recipient_did ?? fromDid!)
        return reply(await packReplyTo(fromDid!, replyKid!, STATUS, { recipient_did: kid, message_count: queue.count(kid) }))
      }

      case DELIVERY_REQUEST: {
        const kid = normalizeKid((msg.body as any)?.recipient_did ?? fromDid!)
        const limit: number = (msg.body as any)?.limit ?? 10
        if (queue.count(kid) === 0) {
          return reply(await packReplyTo(fromDid!, replyKid!, STATUS, { recipient_did: kid, message_count: 0 }))
        }
        // Resolve the reply key BEFORE touching the queue — found live: this
        // used to resolve as part of packReplyTo AFTER queue.take() already
        // ran. take() is destructive (queue.ts splices the batch out), so a
        // resolve failure here — encrypting the reply back to the very device
        // that's asking, a transient did:dht hiccup is enough — silently lost
        // whatever had just been dequeued: the messages were gone from the
        // queue, and the response that would have carried them never sent.
        // Resolving first means a failure here changes nothing; the messages
        // are still queued for the retry.
        let replyKey: { xKid: string; publicKey: Uint8Array }
        try {
          replyKey = await didCommKey(fromDid!, replyKid!)
        } catch (e) {
          return Response.json({ error: `could not resolve reply key: ${e instanceof Error ? e.message : String(e)}` }, { status: 502 })
        }
        const batch = queue.take(kid, limit)
        const attachments = batch.map((packed, i) => ({
          id: `msg-${i}-${crypto.randomUUID()}`,
          data: { json: JSON.parse(packed) },
        }))
        return reply(await packReplyTo(fromDid!, replyKid!, DELIVERY, { recipient_did: kid }, attachments, replyKey))
      }

      default:
        return Response.json({ error: 'unsupported message type', type: msg.type }, { status: 400 })
    }
  }

  return { handle, mediatorDid: mediator.did }
}
