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
import { decodePeerDid2, type PeerIdentity, type PeerDidDoc } from '../../did/peer/peer.ts'
import { buildPlaintext, publicKeyOf, isExpired, type DidCommPlaintext } from '../../did/didcomm/message.ts'
import { buildProblemReport } from '../../did/didcomm/problems.ts'
import { packAuthcrypt, unpackAuthcrypt, unpackAnoncrypt, b64urlToBytes, type DidCommJWE } from '../../did/didcomm/crypto.ts'
import { SeenIds } from '../../did/didcomm/replay.ts'
import { packSigned } from '../../did/didcomm/signature.ts'
import { ResolvedKeyCache } from '../../did/keycache.ts'
import { MessageQueue, QueueFullError } from './queue.ts'
import { ConnectionStore, ConnectionFullError } from './connections.ts'
import { PushSubscriptionStore } from './pushsubs.ts'
import { sendWebPush, type VapidKeys, type WebPushSubscription } from './webpush.ts'

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
const MESSAGES_RECEIVED = 'https://didcomm.org/messagepickup/3.0/messages-received'

// biset's own extension — there is no standard DIDComm protocol for handing a
// mediator a Web Push subscription. Carried as a DIDComm message rather than
// an HTTP endpoint on purpose: the client already holds an authcrypt channel
// here, so `from` is proven, and no second authentication scheme is needed.
const PUSH_SUBSCRIBE = 'https://biset.md/push/1.0/subscribe'
const PUSH_UNSUBSCRIBE = 'https://biset.md/push/1.0/unsubscribe'
const PUSH_ACK = 'https://biset.md/push/1.0/ack'

const DIDCOMM_CT = 'application/didcomm-encrypted+json'

function stripFragment(didOrKidUrl: string): string {
  const i = didOrKidUrl.indexOf('#')
  return i === -1 ? didOrKidUrl : didOrKidUrl.slice(0, i)
}

/** A bare DID → the kid of the key messages for it are actually encrypted to;
 * a kid URL → itself.
 *
 * Forward's `next`, keylist registrations and Pickup's `recipient_did` must all
 * agree on one KID (not just DID) for multi-device delivery to route to the
 * right device's queue (document.ts's DidKeyAgreement note — one kid per
 * device). This used to collapse everything to the bare DID — fine when there
 * was only ever one possible kid, but it silently pooled every device's
 * Forward/queue traffic into one shared bucket once there could be more than
 * one: whichever device polled DELIVERY_REQUEST first drained messages
 * addressed to every OTHER device too, the rest getting nothing.
 *
 * `#k1` used to be appended unconditionally, which is did:dht's naming
 * convention (dht/document.ts) applied to every method. A did:peer recipient's
 * key is `#key-1` (peer.ts), so a did:peer client that named itself by bare DID
 * — which the DIDComm v2 mediator test suite does, and so will any agent that
 * doesn't happen to share biset's own conventions — was registered and looked
 * up under a kid that exists in no document anywhere. did:peer is
 * self-certifying, so the real answer is a decode, not a guess. Other methods
 * keep the `#k1` assumption: it is right for did:dht/did:webvh's first device,
 * and resolving them here would mean a network lookup on every request.
 *
 * NEVER echoed back to a client — see recipientDidOf. */
function normalizeKid(didOrKidUrl: string): string {
  if (didOrKidUrl.includes('#')) return didOrKidUrl
  if (didOrKidUrl.startsWith('did:peer:2.')) {
    try { return xKidOf(decodePeerDid2(didOrKidUrl)) } catch { /* not decodable — fall through */ }
  }
  return `${didOrKidUrl}#k1`
}

/** What to put in a reply's `recipient_did`: EXACTLY the string the client
 * used, never this mediator's internal normalization of it.
 *
 * A client that asked about `did:peer:2.Ez6…` got back `did:peer:2.Ez6…#k1`
 * and could not match the answer to its own question — which is not a cosmetic
 * difference: coordinate-mediation and pickup both identify a recipient by this
 * string, so an agent tracking its own recipients by name sees a reply about
 * somebody it never asked about. The mediator normalizes for its OWN bookkeeping
 * (queue keys, keylist membership); that is an internal detail and stays
 * internal. */
function recipientDidOf(body: unknown, fallback: string): string {
  const asked = (body as { recipient_did?: unknown } | undefined)?.recipient_did
  return typeof asked === 'string' && asked ? asked : fallback
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
  /** Same as `resolveDidDht`, for did:webvh peers (PLANWEBVH.md §5.3). Kept as
   * a separate option rather than a single "resolve any method" function so
   * each method's resolver can fail/degrade independently — a did:webvh
   * outage must not also break did:dht senders and vice versa. */
  resolveDidWebvh?: (did: string, kid: string) => Promise<Uint8Array | null>
  /** OPT-IN server-side multi-hop forwarding (Routing 2.0 Mediator Process): a
   * Forward whose `next` is NOT a locally-registered kid is normally rejected
   * (this mediator is the last hop for its own clients). When this resolver is
   * supplied and returns an endpoint URI for `next`, the mediator instead
   * TRANSMITS the opaque attachment to that URI — the default (non-rewrapping)
   * mediator behaviour, delivering the already-wrapped envelope to the next hop.
   *
   * Left undefined by default ON PURPOSE: a published mediator making arbitrary
   * outbound POSTs is an SSRF surface, so the endpoint policy (scheme allow-
   * listing, no internal hosts, rate limits) belongs to whoever opts in — the
   * resolver returns null to refuse a `next` it won't forward for. */
  forwardResolver?: (next: string) => Promise<string | null>
  /** Web Push for queued Forwards. Without it the mediator queues silently and
   * a closed browser learns nothing until it is next opened — which is the
   * whole reason a relay-less (DID⊥relay) identity had no notifications at all.
   *
   * **Must be the SAME VAPID keypair the relays use.** A Service Worker
   * registration can hold exactly one PushSubscription, bound to the one
   * applicationServerKey it was created with, so a client cannot hold a
   * separate subscription for the mediator (webpush.ts's header). */
  vapid?: VapidKeys
  pushSubs?: PushSubscriptionStore
}

export interface MediatorHandler {
  /** Handles a mediator request, or returns null if the path isn't ours. */
  handle(req: Request, url: URL): Promise<Response | null>
  mediatorDid: string
}

export function createMediator({ mediator, queue = new MessageQueue(), connections = new ConnectionStore(), resolveDidDht, resolveDidWebvh, forwardResolver, vapid, pushSubs = new PushSubscriptionStore() }: MediatorOptions): MediatorHandler {
  const ownRecipient = { kid: mediator.xKid, privateKey: mediator.xPriv }
  // Replay guard over every inbound message's `id` — a re-POSTed anoncrypt
  // Forward would otherwise re-queue the same payload, and a resent authcrypt
  // request would be re-processed (a replayed DELIVERY_REQUEST re-drains a
  // queue). Bounded + TTL'd so it can't itself be turned into a memory DoS.
  const seen = new SeenIds()

  // A did:dht peer's keyAgreement key, cached by kid. This is THE fix for
  // "unstable / slow but eventually arrives": every authenticated request
  // (status, delivery, messages-received, keylist-query) re-resolved the
  // client's OWN key straight from the DHT, so a single un-propagated or
  // rate-limited gateway lookup turned a routine poll into an HTTP 400, and the
  // client only got through once the DHT happened to answer — hence the latency
  // and flakiness. biset's keys are rotation-less and seed-derived, so a given
  // kid maps to ONE stable key: safe to cache. The TTL bounds how long the DHT
  // is skipped entirely (the fast path); past it the key is re-resolved, but a
  // resolve FAILURE still falls back to the last good value rather than
  // erroring — a DHT hiccup must not break a client that already
  // authenticated successfully once.
  //
  // The policy itself lives in did/keycache.ts, shared with the browser's own
  // sender-key cache (didcomm/sender-keys.ts): both sides of the wire cache
  // "the key behind a kid" for the same reason and under the same assumption,
  // and having each write its own version is how the two would drift. One
  // instance for both network-resolved methods (did:dht, did:webvh) — a kid
  // always carries its own DID prefix, so their entries can never collide.
  //
  // Deliberately NOT stale-while-revalidate, unlike the browser's: this is
  // authenticating a request it is about to answer, with no screen waiting on
  // it, so paying for a refresh in-line is fine here.
  const KEY_TTL_MS = 10 * 60 * 1000
  const resolvedKeyCache = new ResolvedKeyCache({ ttlMs: KEY_TTL_MS, label: 'mediator peer key' })

  /** The x25519 key + its kid for a peer identified by any supported method,
   * AT A SPECIFIC device's kid. did:peer is self-certifying and has exactly
   * one key regardless of what `kid` names (decode, no network — the passed
   * kid is ignored, always resolved canonically, and by construction always
   * matches anyway: every did:peer identity in this codebase mints exactly
   * one x25519 key). did:dht/did:webvh are resolved over the network via the
   * injected resolvers, AT `kid` specifically — a relay-less identity
   * (DID⊥relay) can have multiple registered devices, and this is what
   * picks the right one instead of an arbitrary "the" key — then cached
   * (see resolvedKeyCache). */
  async function didCommKey(did: string, kid: string): Promise<{ xKid: string; publicKey: Uint8Array }> {
    if (did.startsWith('did:dht:')) {
      if (!resolveDidDht) throw new Error(`no did:dht resolver configured for ${kid}`)
      const publicKey = await resolvedKeyCache.get(kid, k => resolveDidDht!(did, k))
      return { xKid: kid, publicKey }
    }
    if (did.startsWith('did:webvh:')) {
      if (!resolveDidWebvh) throw new Error(`no did:webvh resolver configured for ${kid}`)
      const publicKey = await resolvedKeyCache.get(kid, k => resolveDidWebvh!(did, k))
      return { xKid: kid, publicKey }
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
  /** Authcrypts an already-built plaintext back to the exact device (`toKid`)
   * that authenticated the request. Shared by ordinary protocol replies and
   * problem-reports. */
  async function packPlaintextTo(
    plaintext: DidCommPlaintext, toDid: string, toKid: string,
    // Pre-resolved key, when the caller already needed to resolve it BEFORE
    // a destructive step (DELIVERY_REQUEST's queue.take() below) and can't
    // afford this function's own resolve to be the one that fails after the
    // fact. Defaults to resolving here, unchanged for every other caller.
    resolvedKey?: { xKid: string; publicKey: Uint8Array },
  ): Promise<string> {
    const { xKid, publicKey } = resolvedKey ?? await didCommKey(toDid, toKid)
    const jwe = packAuthcrypt(
      utf8(JSON.stringify(plaintext)),
      { kid: mediator.xKid, privateKey: mediator.xPriv },
      { kid: xKid, publicKey },
    )
    return JSON.stringify(jwe)
  }

  /** `trigger` is the request being answered. Its thread id becomes the
   * reply's `thid` — threading.md: a message that continues an existing thread
   * carries the `thid` of that thread, and a request with no `thid` of its own
   * IS the thread, so its `id` is what a reply threads onto.
   *
   * Every reply this mediator sent used to omit it. Pickup 3.0 clients
   * correlate a `delivery` with the `delivery-request` that asked for it by
   * exactly this header, so a conforming client got an answer it could not
   * attach to its own outstanding request — the DIDComm v2 mediator test suite
   * dereferences `thid` unconditionally and died on the null. biset's own
   * client happened not to care only because it treats the HTTP response body
   * as the answer to the request it just made. */
  async function packReplyTo(
    trigger: DidCommPlaintext,
    toDid: string, toKid: string, type: string, body: unknown,
    attachments?: DidCommPlaintext['attachments'],
    resolvedKey?: { xKid: string; publicKey: Uint8Array },
  ): Promise<string> {
    const plaintext = buildPlaintext(type, body, mediator.did, toDid, { thid: trigger.thid ?? trigger.id })
    if (attachments) plaintext.attachments = attachments
    return packPlaintextTo(plaintext, toDid, toKid, resolvedKey)
  }

  const reply = (packed: string) => new Response(packed, { status: 200, headers: { 'content-type': DIDCOMM_CT } })

  /** Answers an AUTHENTICATED sender's failed request with a Report Problem 2.0
   * problem-report, authcrypt'd back to it. Returned at HTTP 200 on purpose:
   * in DIDComm the RESPONSE is itself a message, and a logical failure is
   * conveyed by the problem-report's `code`, not by the HTTP status (the client
   * unpacks the body — a non-2xx would make it throw a transport error before
   * ever decrypting the report). `trigger` is the message that failed — its
   * thread becomes the report's `pthid` and its id is ack'd. When the sender
   * isn't authenticated (no key to encrypt to) — e.g. an anoncrypt Forward,
   * which by design has no sender to reply to — falls back to a JSON error at
   * the given transport `status` so an HTTP-only caller still sees a non-2xx. */
  async function problemReply(
    trigger: DidCommPlaintext, fromDid: string | undefined, replyKid: string | undefined,
    status: number, code: string, comment: string, args?: string[],
  ): Promise<Response> {
    if (fromDid && replyKid) {
      const pthid = trigger.thid ?? trigger.id
      // `ack` ONLY when the trigger actually asked for one. The report is
      // already correlated by `pthid`, and an unrequested `ack` is both outside
      // what problems.md asks for and actively harmful in practice — see the
      // header's own note in message.ts.
      const ack = trigger.please_ack?.length ? [trigger.id] : undefined
      const report = buildProblemReport(mediator.did, fromDid, code, comment, { pthid, ack }, args)
      try {
        return reply(await packPlaintextTo(report, fromDid, replyKid))
      } catch { /* sender key unresolvable — fall through to the HTTP error */ }
    }
    return Response.json({ error: comment, code }, { status })
  }

  /** A problem-report the sender can verify but that is addressed to nobody in
   * particular: signed with this mediator's own Ed25519 key and returned
   * unencrypted. For the one case where a request fails and there is no
   * authenticated sender to encrypt an answer back to — an anoncrypt Forward,
   * which by construction hides who sent it. */
  function signedProblem(
    trigger: DidCommPlaintext, toDid: string, code: string, comment: string, args?: string[],
  ): Response {
    const report = buildProblemReport(mediator.did, stripFragment(toDid), code, comment, {
      pthid: trigger.thid ?? trigger.id,
    }, args)
    const jws = packSigned(utf8(JSON.stringify(report)), { kid: mediator.edKid, edPrivateKey: mediator.edPriv })
    // 401, NOT the 200 problemReply uses. The two cases differ in what the
    // response IS: an authcrypt request expects a DIDComm message back, so a
    // non-2xx would make the client throw a transport error before decrypting
    // the explanation. A Forward expects `202 Accepted` and NO message — the
    // sender's only signal is the status, and sendDidComm (send.ts) reads
    // exactly that to decide a device wasn't reached. Answering 200 here would
    // tell every sender their message was delivered to a recipient this
    // mediator just refused to queue for. The report rides in the body for an
    // agent that reads it; the status stays honest for one that doesn't.
    return new Response(JSON.stringify(jws), {
      status: 401,
      headers: { 'content-type': 'application/didcomm-signed+json' },
    })
  }

  /** Refuses a pickup-family request for a kid this client does not own, as a
   * Report Problem 2.0 `e.p.req.not_enroll`. Null when the request is allowed.
   *
   * There was no check here at all. `recipient_did` is a plain field in the
   * request body, and the queue was served for whatever it named — so ANY
   * client that had completed mediate-request could name somebody else's kid
   * and be handed their queued messages, then delete them with
   * messages-received. The payloads stay authcrypt'd to the real recipient, so
   * this never exposed message CONTENT, but it exposed who has mail waiting and
   * how much of it, and it let any registered stranger destroy another user's
   * undelivered messages — the mediator's queue is the only copy until the
   * owner picks it up. The keylist was already the authority for who may
   * RECEIVE at a kid (the FORWARD case has always checked it); this makes it
   * the authority for who may COLLECT from one too.
   *
   * `ownsKey`, not `isAuthorized`: the question is whether THIS connection
   * registered that kid, not whether anyone did. */
  async function denyUnlessOwned(
    msg: DidCommPlaintext, fromDid: string | undefined, replyKid: string | undefined, kid: string,
  ): Promise<Response | null> {
    if (fromDid && connections.ownsKey(fromDid, kid)) return null
    return problemReply(
      msg, fromDid, replyKid, 401, 'e.p.req.not_enroll',
      'no keylist-update from this connection registered {1}', [kid],
    )
  }

  /** Wakes the device that owns `kid`, after something was queued for it.
   *
   * The payload says only how many messages are waiting. It CANNOT say who
   * sent them: a Forward's attachment is opaque to the mediator by design, and
   * the Forward envelope itself is anoncrypt (unpack's own note), so there is
   * no authenticated sender to name even in principle. The Service Worker
   * therefore shows a generic notification — deliberately, rather than
   * teaching it to run a DIDComm pickup, which would mean carrying DID
   * resolution and the whole unpack path into a bundle that has to cold-start
   * inside iOS's background push budget.
   *
   * Fire-and-forget: the sender's 202 must not wait on a third-party push
   * service, and a push that fails is not a delivery failure — the message is
   * queued either way. */
  function notifyPush(kid: string): void {
    if (!vapid) return
    const subs = pushSubs.get(kid)
    if (!subs.length) return
    // loudCount, not count: a device-sync copy of the user's own sent message is
    // queued like anything else but must not be announced. A push that would
    // say "0" is not sent at all — the web has no silent push (Web Push demands
    // a user-visible notification, and browsers penalize a Service Worker that
    // takes one without showing anything), so the ONLY way not to notify is not
    // to push. Delivery doesn't suffer: the recipient's poll still collects it.
    const n = queue.loudCount(kid)
    if (n === 0) return
    const payload = new TextEncoder().encode(JSON.stringify({ t: 'didcomm', n }))
    void (async () => {
      for (const sub of subs) {
        const res = await sendWebPush(sub, vapid, payload)
        // 404/410 means the browser/OS discarded this subscription; drop it
        // everywhere rather than pushing to a dead endpoint forever (the relay
        // side does the same in go-jmapserver's sendOne).
        if (res.expired) pushSubs.removeEndpointEverywhere(sub.endpoint)
        else if (!res.ok) console.warn(`[mediator] push to ${kid} failed: HTTP ${res.status}`)
      }
    })()
  }

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
    // The applicationServerKey a client must subscribe with. Unauthenticated,
    // exactly like the relays' /jmap/push/vapid-public-key — it is a public
    // key, and a relay-less identity (DID⊥relay) has no relay to ask instead,
    // which is the whole case DIDComm push exists for. Empty body when this
    // mediator has no Web Push configured, so a client can tell "not offered"
    // from "unreachable".
    if (req.method === 'GET' && url.pathname === '/didcomm/push/vapid-public-key') {
      return new Response(vapid?.publicKey ?? '', { headers: { 'content-type': 'text/plain' } })
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
    // `from` is the sender's own claim, but authcrypt already proved they hold
    // that DID's key (resolveSenderKey above), so it is safe to trust here.
    //
    // Resolved BEFORE the expiry/replay checks below, which is the whole point:
    // those two used to answer with a bare HTTP 400 because they ran before
    // there was anyone identified to answer to. A DIDComm agent has no model
    // for an HTTP body — the failure has to arrive as a problem-report with a
    // `code`, which is possible here for every authenticated sender.
    const fromDid: string | undefined = msg.from
    if (msg.type !== FORWARD && !fromDid) {
      return Response.json({ error: 'message has no `from` — this message type requires an authenticated sender' }, { status: 400 })
    }
    // Replies go to the EXACT device that authenticated this request
    // (senderKid, authcrypt's own `skid` — `msg.from` is always a bare DID,
    // never naming which device sent it, see normalizeKid's note). FORWARD is
    // anoncrypt (no senderKid) but never replies, so this fallback is
    // defensive only.
    const earlyReplyKid = senderKid ?? (fromDid ? `${fromDid}#k1` : undefined)

    // A message past its own `expires_time` is stale by the sender's own
    // declaration — don't queue or act on it (problems.md "Timeouts").
    if (isExpired(msg)) {
      return problemReply(msg, fromDid, earlyReplyKid, 400, 'e.p.msg.expired', 'message expired (expires_time in the past)')
    }
    // Replay: a second live arrival of the same id is a resend of a message we
    // already handled. Checked AFTER expiry so a stale replay is reported as
    // expired (the more actionable cause) rather than as a duplicate.
    if (!seen.check(msg.id)) {
      return problemReply(msg, fromDid, earlyReplyKid, 400, 'e.p.crypto.message.dejavu', 'message id {1} has already been processed', [msg.id])
    }
    const replyKid = earlyReplyKid

    // Defense in depth around the whole dispatch, on top of DELIVERY_REQUEST's
    // own queue-ordering fix above: found live, an unhandled exception here
    // (any case's packReplyTo hitting a did:dht resolve hiccup) showed up in
    // the anchor's own logs as an uncaught rejection, and the process was
    // observed restarting periodically around the same errors — every
    // in-memory queued message lost on restart (queue.ts's own note: volatile
    // by design). One request that can't be answered must 500, not take the
    // whole mediator down with it.
    try {
      return await dispatch(msg, fromDid, replyKid, senderKid)
    } catch (e) {
      return Response.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 })
    }
  }

  /** `senderKid` is the authcrypt envelope's own `skid` — null when the message
   * arrived anoncrypt, which is the normal case for a forward. Passed separately
   * from `replyKid` because that one falls back to a GUESSED kid when there is
   * no authenticated sender, and an authorization decision must never rest on a
   * guess (the FORWARD case below is one). */
  async function dispatch(msg: DidCommPlaintext, fromDid: string | undefined, replyKid: string | undefined, senderKid: string | null): Promise<Response> {
    switch (msg.type) {
      case MEDIATE_REQUEST: {
        try {
          connections.register(fromDid!)
        } catch (e) {
          if (e instanceof ConnectionFullError) {
            return problemReply(msg, fromDid, replyKid, 503, 'e.p.me.res.storage', 'mediator is at capacity; cannot grant mediation')
          }
          throw e
        }
        return reply(await packReplyTo(msg, fromDid!, replyKid!, MEDIATE_GRANT, { routing_did: mediator.did }))
      }

      case KEYLIST_UPDATE: {
        const updates: Array<{ recipient_did: string; action: 'add' | 'remove' }> = (msg.body as any)?.updates ?? []
        // Per-update result, as Coordinate Mediation 2.0 defines it: one refused
        // key reports itself and the rest still land, rather than the whole
        // batch failing over the last one.
        const updated = updates.map(u => {
          const kid = normalizeKid(u.recipient_did)
          // `no_change` when the request asked for a state the keylist was
          // already in — adding a kid that is registered, removing one that
          // isn't. Coordinate Mediation 2.0 defines it alongside `success`
          // precisely so a client can tell "I did that" from "that was already
          // so"; reporting `success` for a no-op is a lie the client can't
          // detect. NOTE for anyone tightening a client against this: biset's
          // own re-registration adds the same kid on every boot, so a client
          // that treats `no_change` as failure breaks itself — coordinate.ts
          // accepts both.
          let changed = true
          try {
            if (u.action === 'add') changed = connections.addKey(fromDid!, kid, u.recipient_did)
            else {
              changed = connections.removeKey(fromDid!, kid)
              // Everything else this kid owns goes with it. Deregistering used
              // to leave both behind: queued ciphertext nothing would ever
              // collect (harmless while the queue died with the process, a
              // 30-day disk resident now that it doesn't), and a push
              // subscription that kept waking a browser which had logged this
              // device out and could no longer decrypt a thing.
              queue.clear(kid)
              pushSubs.removeKid(kid)
            }
          } catch (e) {
            if (e instanceof ConnectionFullError) {
              return { recipient_did: u.recipient_did, action: u.action, result: 'server_error' }
            }
            throw e
          }
          return { recipient_did: u.recipient_did, action: u.action, result: changed ? 'success' : 'no_change' }
        })
        return reply(await packReplyTo(msg, fromDid!, replyKid!, KEYLIST_UPDATE_RESPONSE, { updated }))
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
        // `last_seen` (epoch ms, omitted when this kid has never picked
        // anything up) is a biset extension to the spec's keylist entry —
        // additive, so a conforming client that only reads `recipient_did`
        // is unaffected. It exists so a user's own device list can name the
        // ghosts (connections.ts's lastSeen); nothing on either side ever
        // deletes a key because of it.
        const keys = connections.listKeysWithActivity(fromDid!)
        return reply(await packReplyTo(msg, fromDid!, replyKid!, KEYLIST, {
          // The client's OWN spelling of each kid (connections.ts's asGiven),
          // not this mediator's normalization of it — a keylist answered in
          // terms the client never used is one it cannot reconcile with what it
          // registered.
          keys: keys.map(k => k.lastSeen === undefined
            ? { recipient_did: k.asGiven }
            : { recipient_did: k.asGiven, last_seen: k.lastSeen }),
        }))
      }

      case PUSH_SUBSCRIBE:
      case PUSH_UNSUBSCRIBE: {
        if (!vapid) {
          return problemReply(msg, fromDid, replyKid, 501, 'e.p.me.res.storage', 'this mediator has no Web Push configured')
        }
        const body = (msg.body ?? {}) as { recipient_did?: string; endpoint?: string; keys?: { p256dh?: string; auth?: string } }
        const kid = normalizeKid(body.recipient_did ?? fromDid!)
        // The kid must be one THIS client registered. Without this check anyone
        // could attach their own endpoint to someone else's kid and get woken
        // on every message that person receives — not the contents, but the
        // timing and volume of their correspondence, which is plenty.
        if (!connections.listKeys(fromDid!).includes(kid)) {
          return problemReply(msg, fromDid, replyKid, 401, 'e.p.msg.no-route', 'recipient_did is not in this connection keylist', [kid])
        }
        if (!body.endpoint) {
          return problemReply(msg, fromDid, replyKid, 400, 'e.p.msg.invalid', 'push subscription is missing `endpoint`')
        }
        if (msg.type === PUSH_UNSUBSCRIBE) {
          pushSubs.remove(kid, body.endpoint)
          return reply(await packReplyTo(msg, fromDid!, replyKid!, PUSH_ACK, { recipient_did: kid, subscribed: false }))
        }
        if (!body.keys?.p256dh || !body.keys?.auth) {
          return problemReply(msg, fromDid, replyKid, 400, 'e.p.msg.invalid', 'push subscription is missing `keys.p256dh`/`keys.auth`')
        }
        const sub: WebPushSubscription = {
          endpoint: body.endpoint,
          keys: { p256dh: body.keys.p256dh, auth: body.keys.auth },
        }
        pushSubs.add(kid, sub)
        return reply(await packReplyTo(msg, fromDid!, replyKid!, PUSH_ACK, { recipient_did: kid, subscribed: true }))
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
          // Not one of our own registered clients. If server-side multi-hop is
          // enabled and the resolver will vouch for an endpoint, transmit the
          // opaque attachment onward (Routing 2.0 Mediator Process) instead of
          // refusing. Otherwise this mediator is the last hop and the kid is
          // simply unknown to it.
          if (forwardResolver) {
            let endpoint: string | null = null
            try { endpoint = await forwardResolver(next) } catch { endpoint = null }
            if (endpoint) {
              try {
                const onward = await fetch(endpoint, { method: 'POST', headers: { 'content-type': DIDCOMM_CT }, body: JSON.stringify(forwarded) })
                if (!onward.ok) return Response.json({ error: `onward forward failed: HTTP ${onward.status}` }, { status: 502 })
                return new Response(null, { status: 202 })
              } catch (e) {
                return Response.json({ error: `onward forward transport error: ${e instanceof Error ? e.message : String(e)}` }, { status: 502 })
              }
            }
          }
          // A SIGNED problem-report, not a bare HTTP error. A forward is
          // anoncrypt by design, so there is no authenticated sender to
          // authcrypt a reply to — but "I will not queue for that kid" is
          // still something the sender must be able to act on, and signing
          // proves which mediator said it (signature.md: a signed, unencrypted
          // message is exactly the case where the recipient is unknown but the
          // origin must be provable). The sender was previously left with a
          // 401 body that no DIDComm agent models.
          return signedProblem(msg, next, 'e.p.req.not_enroll', 'no keylist-update registered {1}', [kid])
        }
        // Device sync, recognized rather than declared. A forward is normally
        // anoncrypt — routing's whole point is that the mediator learns where
        // to queue, not who sent it — and stays that way for every message to
        // someone else. But when a device fans its own just-sent message out to
        // ITS OWN other devices (channel.ts's syncToSiblingDevices), it
        // authcrypts the outer envelope to this mediator, which it is already a
        // registered client of. That gives an authenticated senderKid, and the
        // sibling test is then a lookup in this mediator's OWN keylist: is
        // `next` a kid of the same connection the sender registered?
        //
        // Both halves matter. Authenticated, so no stranger can claim it (the
        // alternative — a "don't notify" flag on the message — would be settable
        // by anyone, since an anoncrypt forward has no sender, turning every
        // passer-by into someone who can silence your phone). Recognized from
        // existing state, so nothing new is disclosed: this mediator wrote that
        // keylist itself and has always known which kids share an identity.
        const senderDid = senderKid?.split('#')[0]
        const silent = !!senderDid && connections.ownsKey(senderDid, kid)
        try {
          queue.push(kid, JSON.stringify(forwarded), { silent })
          // Not merely "push a smaller number": no push at all for a sync-only
          // arrival. Pushing with an unchanged loud count would re-announce an
          // older message that was already notified for.
          if (!silent) notifyPush(kid)
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
        const asked = recipientDidOf(msg.body, fromDid!)
        const denied = await denyUnlessOwned(msg, fromDid, replyKid, kid)
        if (denied) return denied
        connections.touch(kid)
        return reply(await packReplyTo(msg, fromDid!, replyKid!, STATUS, { recipient_did: asked, message_count: queue.count(kid) }))
      }

      case DELIVERY_REQUEST: {
        const kid = normalizeKid((msg.body as any)?.recipient_did ?? fromDid!)
        const asked = recipientDidOf(msg.body, fromDid!)
        const denied = await denyUnlessOwned(msg, fromDid, replyKid, kid)
        if (denied) return denied
        // Any authenticated pickup-family request proves the device behind this
        // kid still exists — the one signal that separates a live device from a
        // ghost slot left by a cleared browser (connections.ts's lastSeen).
        // Recorded before the early return below: "asked and there was nothing"
        // is exactly as much proof of life as "collected a message".
        connections.touch(kid)
        const limit: number = (msg.body as any)?.limit ?? 10
        if (queue.count(kid) === 0) {
          return reply(await packReplyTo(msg, fromDid!, replyKid!, STATUS, { recipient_did: asked, message_count: 0 }))
        }
        // Resolve the reply key before building the response. Pickup 3.0
        // delivery is NON-destructive (queue.peek, not a splice) — messages are
        // only removed later, on `messages-received` — so a resolve failure
        // here loses nothing; the batch stays queued for the retry. A failure
        // still 502s so the client's pickup errors clearly rather than silently
        // returning empty.
        let replyKey: { xKid: string; publicKey: Uint8Array }
        try {
          replyKey = await didCommKey(fromDid!, replyKid!)
        } catch (e) {
          return Response.json({ error: `could not resolve reply key: ${e instanceof Error ? e.message : String(e)}` }, { status: 502 })
        }
        // Each attachment's id is the mediator's own queue id for the message —
        // the value the recipient names back in `messages-received` to have it
        // removed. It MUST be the queue id, not the inner message's own id
        // (which the mediator can't read — the payload is opaque/encrypted).
        const batch = queue.peek(kid, limit)
        const attachments = batch.map(m => ({ id: m.id, data: { json: JSON.parse(m.packed) } }))
        return reply(await packReplyTo(msg, fromDid!, replyKid!, DELIVERY, { recipient_did: asked }, attachments, replyKey))
      }

      case MESSAGES_RECEIVED: {
        // Pickup 3.0 messages-received: the recipient confirms it has stored the
        // listed queue ids, which are now safe to drop. Idempotent — re-acking
        // an already-removed id is a no-op, so a retried ack can't error.
        //
        // The body is `{message_id_list}` and NOTHING ELSE — Pickup 3.0 does not
        // put `recipient_did` on this message, unlike status-request and
        // delivery-request. This used to fall back to the SENDER's own DID and
        // clear that queue, which is only the right one when a client's
        // registered kid happens to be derived from the DID it authenticates
        // with. biset's own client satisfies that by construction, so this was
        // invisible here; a client that registered a separate recipient kid
        // (the ordinary DIDComm pattern, and what the test suite does) ack'd
        // into an empty queue while the real one kept redelivering the same
        // batch forever.
        //
        // Queue ids are unique across this mediator, so the answer needs no
        // hint from the client: remove the named ids from every kid THIS
        // connection owns. Scoped to the connection, so an id belonging to
        // someone else is untouched no matter who names it.
        const ids: string[] = (msg.body as any)?.message_id_list ?? []
        const named = (msg.body as any)?.recipient_did
        const kids = typeof named === 'string' && named
          ? [normalizeKid(named)]
          : connections.listKeys(fromDid!)
        if (typeof named === 'string' && named) {
          const denied = await denyUnlessOwned(msg, fromDid, replyKid, kids[0]!)
          if (denied) return denied
        }
        let remaining = 0
        for (const kid of kids) {
          connections.touch(kid)
          remaining += queue.remove(kid, ids)
        }
        const body: Record<string, unknown> = { message_count: remaining }
        // Only echo a recipient the client actually named — inventing one would
        // report a per-kid count for a request that was never about one kid.
        if (typeof named === 'string' && named) body.recipient_did = named
        return reply(await packReplyTo(msg, fromDid!, replyKid!, STATUS, body))
      }

      default:
        return problemReply(msg, fromDid, replyKid, 400, 'e.p.msg.unsupported', 'unsupported message type {1}', [msg.type])
    }
  }

  return { handle, mediatorDid: mediator.did }
}
