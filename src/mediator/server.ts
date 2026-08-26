// The DIDComm v2 mediator: Coordinate Mediation 2.0, Routing 2.0, Pickup 3.0.
// A client that can't hold a socket open (a browser) registers here, gives
// the mediator's URL out as its own DIDComm endpoint, and collects what
// arrives whenever it's next running.
//
// blind by construction (ARC.md's DIDComm mediator redesign, 2026-08-27):
// this module has NO import from biset-core, `roster/`, or `vault/` -- it
// knows nothing about identities beyond a did:webvh string and a kid, and it
// cannot decrypt a single byte it relays. It is a separate deploy unit from
// biset-core on purpose (src/mediator/index.ts), so that property can never
// quietly regress via a shared process/DB.
//
// Ported from src.bak/anchor/mediator/server.ts, trimmed to Coordinate
// Mediation 2.0 + Routing 2.0 Forward + Pickup 3.0 -- MLS transport
// (mls-transport.ts/mls-ds.ts) is out of scope (biset's MLS DS is a
// different wire protocol, core/mediation/mls-delivery-store.ts, already
// live) and Web Push is deferred (design doc's Phase 3 minimum).
import { decodePeerDid2, publicKeyOf, type PeerIdentity, type PeerDidDoc } from '../didcomm/peer.ts'
import { buildPlaintext, isExpired, type DidCommPlaintext } from '../didcomm/message.ts'
import { buildProblemReport } from '../didcomm/problems.ts'
import {
  packAuthcrypt, unpackAuthcrypt, unpackAnoncrypt, b64urlToBytes, parseJwe, protectedHeaderOf,
  type DidCommJWE,
} from '../didcomm/crypto.ts'
import { SeenIds } from './replay.ts'
import { packSigned } from './signature.ts'
import { ResolvedKeyCache } from './keycache.ts'
import { MessageQueue, QueueFullError } from './queue.ts'
import { ConnectionStore, ConnectionFullError } from './connections.ts'
import {
  MEDIATE_REQUEST, MEDIATE_GRANT, KEYLIST_UPDATE, KEYLIST_UPDATE_RESPONSE, KEYLIST_QUERY, KEYLIST,
  FORWARD, STATUS_REQUEST, STATUS, DELIVERY_REQUEST, DELIVERY, MESSAGES_RECEIVED,
} from '../didcomm/mediator-protocol.ts'

const DIDCOMM_CT = 'application/didcomm-encrypted+json'

function stripFragment(didOrKidUrl: string): string {
  const i = didOrKidUrl.indexOf('#')
  return i === -1 ? didOrKidUrl : didOrKidUrl.slice(0, i)
}

/** A bare DID → the kid of the key messages for it are actually encrypted to;
 * a kid URL → itself.
 *
 * A did:webvh recipient names its didCommKid explicitly (identity-shared
 * since the 2026-08-27 redesign -- ONE kid per identity, not per device), so
 * a bare DID here is a client that omitted the fragment; falling back to
 * `#didcomm` matches identity/bootstrap.ts's own kid-naming
 * (didcomm/devicekid.ts). A did:peer recipient's key is self-certifying and
 * decodes straight out of the DID string.
 *
 * NEVER echoed back to a client -- see recipientDidOf. */
function normalizeKid(didOrKidUrl: string): string {
  if (didOrKidUrl.includes('#')) return didOrKidUrl
  if (didOrKidUrl.startsWith('did:peer:2.')) {
    try { return decodePeerDid2(didOrKidUrl).keyAgreement[0] ?? didOrKidUrl } catch { /* not decodable -- fall through */ }
  }
  return didOrKidUrl
}

/** What to put in a reply's `recipient_did`: EXACTLY the string the client
 * used, never this mediator's internal normalization of it. */
function recipientDidOf(body: unknown, fallback: string): string {
  const asked = (body as { recipient_did?: unknown } | undefined)?.recipient_did
  return typeof asked === 'string' && asked ? asked : fallback
}

function docFor(did: string): PeerDidDoc {
  return decodePeerDid2(did)
}

function xKidOf(doc: PeerDidDoc): string {
  const kid = doc.keyAgreement[0]
  if (!kid) throw new Error(`${doc.id} has no keyAgreement key`)
  return kid
}

const utf8 = (s: string) => new TextEncoder().encode(s)
const toHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')
const fromHex = (h: string): Uint8Array => new Uint8Array((h.match(/../g) ?? []).map(x => parseInt(x, 16)))

export interface MediatorOptions {
  mediator: PeerIdentity
  queue?: MessageQueue
  connections?: ConnectionStore
  /** Resolve a `did:webvh` peer's DIDComm key (X25519) at a SPECIFIC kid --
   * needed to authenticate senders and encrypt replies that identify by
   * did:webvh rather than the self-certifying did:peer. Without this option
   * the mediator handles did:peer clients only. `didcomm/webvh-resolve.ts`'s
   * `resolveDidCommSenderKey` is a ready-made implementation -- pure HTTP
   * against the public did:webvh log, no biset-core dependency. */
  resolveDidWebvh?: (did: string, kid: string) => Promise<Uint8Array | null>
}

export interface MediatorHandler {
  /** Handles a mediator request, or returns null if the path isn't ours. */
  handle(req: Request, url: URL): Promise<Response | null>
  mediatorDid: string
}

export function createMediator({ mediator, queue = new MessageQueue(), connections = new ConnectionStore(), resolveDidWebvh }: MediatorOptions): MediatorHandler {
  const ownRecipient = { kid: mediator.xKid, privateKey: mediator.xPriv }
  // Replay guard over every inbound message's `id` -- a re-POSTed anoncrypt
  // Forward would otherwise re-queue the same payload, and a resent
  // authcrypt request would be re-processed.
  const seen = new SeenIds()

  // A did:webvh peer's keyAgreement key, cached by kid -- avoids a network
  // resolve on every authenticated pickup poll. biset's DIDComm keys are
  // rotation-less (identity-shared, minted once per identity), so a kid maps
  // to one key for as long as it exists at all: safe to cache with a long
  // TTL, falling back to the last good value on a resolve failure.
  const KEY_TTL_MS = 10 * 60 * 1000
  const resolvedKeyCache = new ResolvedKeyCache({ ttlMs: KEY_TTL_MS, label: 'mediator peer key' })

  /** The X25519 key + its kid for a peer identified by any supported method,
   * AT A SPECIFIC kid. did:peer is self-certifying (decode, no network).
   * did:webvh is resolved over the network via the injected resolver, then
   * cached. */
  async function didCommKey(did: string, kid: string): Promise<{ xKid: string; publicKey: Uint8Array }> {
    if (did.startsWith('did:webvh:')) {
      if (!resolveDidWebvh) throw new Error(`no did:webvh resolver configured for ${kid}`)
      const publicKey = await resolvedKeyCache.get(kid, async k => {
        const key = await resolveDidWebvh!(did, k)
        if (!key) throw new Error(`${kid} did not resolve`)
        return key
      })
      return { xKid: kid, publicKey }
    }
    const doc = docFor(did)
    const canonicalKid = xKidOf(doc)
    return { xKid: canonicalKid, publicKey: publicKeyOf(doc, canonicalKid) }
  }

  /** The sender's key, at the exact kid it claimed (authcrypt's own `skid`
   * header, not `msg.from` -- a bare DID never names which device sent it). */
  async function resolveSenderKey(senderKid: string): Promise<Uint8Array> {
    // A kid this mediator has already registered authenticates against the
    // key it registered WITH, not against whatever the identity's document
    // says right now -- resolving every time makes a device's ability to
    // talk to its own mediator depend on a third document's live state
    // (src.bak's server.ts documents the 2026-08-13 production incident this
    // avoids). Safe because biset's didCommKid is derived from the key
    // itself (didcomm/devicekid.ts): kid → key is one-to-one and permanent.
    const registered = connections.keyFor(senderKid)
    if (registered) return fromHex(registered)
    const did = stripFragment(senderKid)
    return (await didCommKey(did, senderKid)).publicKey
  }

  /** Authcrypts an already-built plaintext back to the exact device (`toKid`)
   * that authenticated the request. */
  async function packPlaintextTo(
    plaintext: DidCommPlaintext, toDid: string, toKid: string,
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

  /** `trigger` is the request being answered; its thread id becomes the
   * reply's `thid` (threading.md). */
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

  /** Answers an AUTHENTICATED sender's failed request with a Report Problem
   * 2.0 problem-report, authcrypt'd back to it, at HTTP 200 (in DIDComm the
   * RESPONSE is itself a message; the failure lives in the report's `code`).
   * Falls back to a JSON error at `status` when there is no authenticated
   * sender to encrypt a reply to. */
  async function problemReply(
    trigger: DidCommPlaintext, fromDid: string | undefined, replyKid: string | undefined,
    status: number, code: string, comment: string, args?: string[],
  ): Promise<Response> {
    if (fromDid && replyKid) {
      const pthid = trigger.thid ?? trigger.id
      const ack = trigger.please_ack?.length ? [trigger.id] : undefined
      const report = buildProblemReport(mediator.did, fromDid, code, comment, { pthid, ack }, args)
      try {
        return reply(await packPlaintextTo(report, fromDid, replyKid))
      } catch { /* sender key unresolvable -- fall through to the HTTP error */ }
    }
    return Response.json({ error: comment, code }, { status })
  }

  /** A problem-report the sender can verify but that is addressed to
   * nobody in particular: signed with this mediator's own Ed25519 key and
   * returned unencrypted. For the one case where a request fails and there
   * is no authenticated sender to encrypt an answer back to -- an anoncrypt
   * Forward, which by construction hides who sent it. */
  function signedProblem(
    trigger: DidCommPlaintext, toDid: string, code: string, comment: string, args?: string[],
  ): Response {
    const report = buildProblemReport(mediator.did, stripFragment(toDid), code, comment, {
      pthid: trigger.thid ?? trigger.id,
    }, args)
    const jws = packSigned(utf8(JSON.stringify(report)), { kid: mediator.edKid, edPrivateKey: mediator.edPriv })
    // 401, not the 200 problemReply uses: a Forward expects `202 Accepted`
    // and no message, so the sender's only signal is the HTTP status
    // (sendDidComm-style callers read exactly that to decide a recipient
    // wasn't reached). Answering 200 would tell every sender their message
    // was delivered to a recipient this mediator just refused to queue for.
    return new Response(JSON.stringify(jws), {
      status: 401,
      headers: { 'content-type': 'application/didcomm-signed+json' },
    })
  }

  /** Refuses a pickup-family request for a kid this client does not own, as
   * a Report Problem 2.0 `e.p.req.not_enroll`. Null when allowed. `ownsKey`,
   * not `isAuthorized`: the question is whether THIS connection registered
   * that kid, not whether anyone did -- otherwise any registered stranger
   * could collect (and then delete, via messages-received) somebody else's
   * queued messages. */
  async function denyUnlessOwned(
    msg: DidCommPlaintext, fromDid: string | undefined, replyKid: string | undefined, kid: string,
  ): Promise<Response | null> {
    if (fromDid && connections.ownsKey(fromDid, kid)) return null
    return problemReply(
      msg, fromDid, replyKid, 401, 'e.p.req.not_enroll',
      'no keylist-update from this connection registered {1}', [kid],
    )
  }

  /** A body this mediator refuses to read, with a reason it is willing to
   * say out loud. */
  class Malformed extends Error {}

  /** Unpacks either flavour. The `alg` header decides: Forward is anoncrypt
   * by design -- the whole point of routing is that the mediator learns
   * where to queue, not who sent it -- while everything else is authcrypt'd
   * and carries a verified sender. */
  async function unpack(raw: string): Promise<{ msg: DidCommPlaintext; senderKid: string | null }> {
    let body: unknown
    try {
      body = JSON.parse(raw)
    } catch {
      throw new Malformed('body is not JSON')
    }
    const jwe = parseJwe(body)
    if (!jwe) throw new Malformed('body is not a DIDComm JWE')
    const header = protectedHeaderOf(jwe)
    if (!header) throw new Malformed('the protected header is not readable')
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
      if (e instanceof Malformed) {
        return Response.json({ error: e.message }, { status: 400 })
      }
      console.error('[mediator] could not unpack an inbound message:', e)
      return Response.json({ error: 'could not read this message' }, { status: 400 })
    }

    if (typeof msg.id !== 'string' || !msg.id) {
      return Response.json({ error: 'message has no `id`' }, { status: 400 })
    }
    // `from` is the sender's own claim, but authcrypt already proved they
    // hold that DID's key (resolveSenderKey above), so it is safe to trust
    // here.
    const fromDid: string | undefined = msg.from
    if (msg.type !== FORWARD && !fromDid) {
      return Response.json({ error: 'message has no `from` -- this message type requires an authenticated sender' }, { status: 400 })
    }
    // Replies go to the EXACT device that authenticated this request
    // (senderKid, authcrypt's own `skid`). FORWARD is anoncrypt (no
    // senderKid) but never replies, so this fallback is defensive only.
    const earlyReplyKid = senderKid ?? (fromDid ? normalizeKid(fromDid) : undefined)

    if (isExpired(msg)) {
      return problemReply(msg, fromDid, earlyReplyKid, 400, 'e.p.msg.expired', 'message expired (expires_time in the past)')
    }
    if (!seen.check(msg.id)) {
      return problemReply(msg, fromDid, earlyReplyKid, 400, 'e.p.crypto.message.dejavu', 'message id {1} has already been processed', [msg.id])
    }
    const replyKid = earlyReplyKid

    // Defense in depth: one request that can't be answered must 500, not
    // take the whole mediator down with it.
    try {
      return await dispatch(msg, fromDid, replyKid, senderKid)
    } catch (e) {
      return Response.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 })
    }
  }

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
        const updated = await Promise.all(updates.map(async u => {
          const kid = normalizeKid(u.recipient_did)
          // `no_change` when the request asked for a state the keylist was
          // already in -- Coordinate Mediation 2.0 defines it alongside
          // `success` so a client can tell "I did that" from "that was
          // already so".
          let changed = true
          try {
            if (u.action === 'add') {
              // The key this request authenticated with is the published
              // one -- that is what unpacking it just proved. Recorded now
              // so later requests from this device need no document at all.
              const registering = senderKid === kid
                ? await resolveSenderKey(senderKid).then(toHex).catch(() => undefined)
                : undefined
              changed = connections.addKey(fromDid!, kid, u.recipient_did, registering)
            } else {
              changed = connections.removeKey(fromDid!, kid)
              // A deregistered device is gone: everything it owns goes with
              // it -- queued ciphertext nothing will ever collect.
              queue.clear(kid)
            }
          } catch (e) {
            if (e instanceof ConnectionFullError) {
              return { recipient_did: u.recipient_did, action: u.action, result: 'server_error' }
            }
            throw e
          }
          return { recipient_did: u.recipient_did, action: u.action, result: changed ? 'success' : 'no_change' }
        }))
        return reply(await packReplyTo(msg, fromDid!, replyKid!, KEYLIST_UPDATE_RESPONSE, { updated }))
      }

      case KEYLIST_QUERY: {
        // Returns the kids THIS authenticated client (fromDid = the
        // identity's shared DID across all its devices) currently has
        // registered -- the authoritative live-device set. Authenticated by
        // construction: fromDid comes from the authcrypt envelope, so a
        // client can only ever read its own keylist.
        const keys = connections.listKeysWithActivity(fromDid!)
        return reply(await packReplyTo(msg, fromDid!, replyKid!, KEYLIST, {
          keys: keys.map(k => k.lastSeen === undefined
            ? { recipient_did: k.asGiven }
            : { recipient_did: k.asGiven, last_seen: k.lastSeen }),
        }))
      }

      case FORWARD: {
        // Routing 2.0's shape: `next` in the body, the opaque re-wrapped JWE
        // as the single attachment. Never decrypted -- we can't, and that's
        // the point.
        const next = (msg.body as any)?.next
        const forwarded = msg.attachments?.[0]?.data?.json
        if (!next || forwarded === undefined) {
          return Response.json({ error: 'forward is missing `next` or its attachment' }, { status: 400 })
        }
        const kid = normalizeKid(next)
        if (!connections.isAuthorized(kid)) {
          // A SIGNED problem-report, not a bare HTTP error: a forward is
          // anoncrypt by design, so there is no authenticated sender to
          // authcrypt a reply to, but "I will not queue for that kid" is
          // still something the sender must be able to act on.
          return signedProblem(msg, next, 'e.p.req.not_enroll', 'no keylist-update registered {1}', [kid])
        }
        try {
          queue.push(kid, JSON.stringify(forwarded))
        } catch (e) {
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
        // Any authenticated pickup-family request proves the device behind
        // this kid still exists -- recorded before the early return below,
        // since "asked and there was nothing" is exactly as much proof of
        // life as "collected a message".
        connections.touch(kid)
        const limit: number = (msg.body as any)?.limit ?? 10
        if (queue.count(kid) === 0) {
          return reply(await packReplyTo(msg, fromDid!, replyKid!, STATUS, { recipient_did: asked, message_count: 0 }))
        }
        // Resolve the reply key BEFORE building the response. Pickup 3.0
        // delivery is NON-destructive (peek, not a splice), so a resolve
        // failure here loses nothing -- the batch stays queued for retry.
        let replyKey: { xKid: string; publicKey: Uint8Array }
        try {
          replyKey = await didCommKey(fromDid!, replyKid!)
        } catch (e) {
          return Response.json({ error: `could not resolve reply key: ${e instanceof Error ? e.message : String(e)}` }, { status: 502 })
        }
        // Each attachment's id is the mediator's own queue id -- the value
        // the recipient names back in `messages-received` to have it
        // removed. It MUST be the queue id, not the inner message's own id
        // (the payload is opaque/encrypted -- the mediator can't read it).
        const batch = queue.peek(kid, limit)
        const attachments = batch.map(m => ({ id: m.id, data: { json: JSON.parse(m.packed) } }))
        return reply(await packReplyTo(msg, fromDid!, replyKid!, DELIVERY, { recipient_did: asked }, attachments, replyKey))
      }

      case MESSAGES_RECEIVED: {
        // Pickup 3.0's body is `{message_id_list}` and NOTHING ELSE -- no
        // `recipient_did`, unlike status-request/delivery-request. Queue ids
        // are unique across this mediator, so the answer needs no hint from
        // the client: remove the named ids from every kid THIS connection
        // owns.
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
        if (typeof named === 'string' && named) body.recipient_did = named
        return reply(await packReplyTo(msg, fromDid!, replyKid!, STATUS, body))
      }

      default:
        return problemReply(msg, fromDid, replyKid, 400, 'e.p.msg.not-recognized', 'unrecognized message type {1}', [msg.type])
    }
  }

  return { handle, mediatorDid: mediator.did }
}
