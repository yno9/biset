// Mail Mediator DIDComm dispatch: route-bind, pickup-request,
// messages-received, submit, submit-status-request
// (PLAN_biset-mail-mediator.md section 4).
//
// Shares its request/reply SKELETON with src/mediator/server.ts (unpack ->
// replay check -> dispatch -> pack reply, same crypto/message-building
// calls) but never its state: route-store.ts/spool-store.ts/
// submission-store.ts are Mail-specific, and this module has NO import
// from biset-core, `roster/`, or `vault/` -- same "blind by construction"
// boundary as the DIDComm mediator, for the same reason (PLAN section 2
// "所有しないもの": Vault ID, MLS group, device roster, mail/JMAP
// projection are all out of scope here).
//
// Two authentication tiers, not one: `route-bind` must arrive authcrypt'd
// from the address's PUBLIC mail operational kid (verified against its
// did:webvh routing document via `resolveMailOperationalKid`); every other
// message type must arrive from a `relationshipKid` this mediator already
// bound for that address (route-store.ts's own index). A route-bind from
// an already-bound relationship kid, or a pickup/submit from the front-door
// kid, are both refused -- PLAN section 4 steps 4-5 draw that line on
// purpose (front-door kid: initial contact only; relationship kid: all
// continuing operations).
//
// `resolveMailOperationalKid` resolves BY KID ALONE, not `(address, kid)`:
// route-bind's claimed address lives inside the still-encrypted JWE body,
// so nothing outside it is known before the sender's key is resolved and
// the ciphertext opened. Resolving from the kid's own DID (whatever the
// resolver reads to answer -- routing.json/alsoKnownAs) breaks that
// ordering problem, and the address it reports back is then checked
// against what route-bind's body actually claims (dispatch's ROUTE_BIND
// case) -- an address mismatch is treated as a forged claim, not trusted.
import { type PeerIdentity } from '../didcomm/peer.ts'
import { buildPlaintext, isExpired, type DidCommPlaintext } from '../didcomm/message.ts'
import { buildProblemReport } from '../didcomm/problems.ts'
import { packAuthcrypt, unpackAuthcrypt, parseJwe, protectedHeaderOf } from '../didcomm/crypto.ts'
import type { ReplayGuard } from '../mediator/replay.ts'
import { SeenIds } from '../mediator/replay.ts'
import {
  ROUTE_BIND, ROUTE_BIND_RESULT, PICKUP_REQUEST, PICKUP, MESSAGES_RECEIVED, SUBMIT, SUBMIT_STATUS_REQUEST, SUBMIT_RESULT,
  routeBindBodyOf, pickupItemToWire, submitBodyOf,
  type RouteBindResultBody, type PickupBody, type PickupRequestBody, type MessagesReceivedBody,
  type SubmitStatusRequestBody, type SubmitResultBody,
} from './protocol.ts'
import { RouteStore, RouteStoreFullError, type MailRouteStore } from './route-store.ts'
import { SpoolStore, type MailSpoolStore } from './spool-store.ts'
import { SubmissionStore, SubmissionStoreFullError, type MailSubmissionStore, type RecipientResult, type SubmissionRecord } from './submission-store.ts'

const DIDCOMM_CT = 'application/didcomm-encrypted+json'
const DEFAULT_PICKUP_LEASE_MS = 5 * 60 * 1000

export interface MailMediatorOptions {
  mediator: PeerIdentity
  routes?: MailRouteStore
  spool?: MailSpoolStore
  submissions?: MailSubmissionStore
  replay?: ReplayGuard
  /** Synchronous transaction shared by durable replay/route/spool stores. */
  transaction?: <T>(operation: () => T) => T
  /** Resolves a kid to the address it is currently published as this
   * mediator's front-door mail operational key for, plus the key itself.
   * Null means "does not resolve as a mail operational kid at all" (not
   * every kid needs to -- a relationship kid never reaches this resolver,
   * see resolveSender below). Pure HTTP against the public did:webvh
   * routing document, no biset-core dependency. */
  resolveMailOperationalKid: (kid: string) => Promise<{ address: string; publicKey: Uint8Array } | null>
  /** Actually dials SMTP for an acquired submission and returns each
   * recipient's outcome. Invoked fire-and-forget from the `submit`
   * handler (async model -- PLAN section 12, revised): the client polls
   * `submit-status-request` for the result instead of blocking the
   * `submit` round trip on SMTP dialogue. A throw is treated as a
   * temporary-failure for every recipient, never left permanently
   * in-flight. */
  submitOutbound: (record: SubmissionRecord) => Promise<RecipientResult[]>
  now?: () => string
  pickupLeaseMs?: number
}

export interface MailMediatorHandler {
  handle(req: Request, url: URL): Promise<Response | null>
  mediatorDid: string
}

export function createMailMediator({
  mediator,
  routes = new RouteStore(),
  spool = new SpoolStore(),
  submissions = new SubmissionStore(),
  replay = new SeenIds(),
  transaction = operation => operation(),
  resolveMailOperationalKid,
  submitOutbound,
  now = () => new Date().toISOString(),
  pickupLeaseMs = DEFAULT_PICKUP_LEASE_MS,
}: MailMediatorOptions): MailMediatorHandler {
  const ownRecipient = { kid: mediator.xKid, privateKey: mediator.xPriv }
  const seen = replay

  async function packPlaintextTo(plaintext: DidCommPlaintext, toKid: string, publicKey: Uint8Array): Promise<string> {
    const jwe = packAuthcrypt(
      new TextEncoder().encode(JSON.stringify(plaintext)),
      { kid: mediator.xKid, privateKey: mediator.xPriv },
      { kid: toKid, publicKey },
    )
    return JSON.stringify(jwe)
  }

  async function packReplyTo(
    trigger: DidCommPlaintext, toDid: string, toKid: string, publicKey: Uint8Array, type: string, body: unknown,
  ): Promise<string> {
    const plaintext = buildPlaintext(type, body, mediator.did, toDid, { thid: trigger.thid ?? trigger.id })
    return packPlaintextTo(plaintext, toKid, publicKey)
  }

  const reply = (packed: string) => new Response(packed, { status: 200, headers: { 'content-type': DIDCOMM_CT } })

  async function problemReply(
    trigger: DidCommPlaintext, fromDid: string | undefined, replyKid: string | undefined, replyKey: Uint8Array | undefined,
    status: number, code: string, comment: string, args?: string[],
  ): Promise<Response> {
    if (fromDid && replyKid && replyKey) {
      const report = buildProblemReport(mediator.did, fromDid, code, comment, { pthid: trigger.thid ?? trigger.id }, args)
      try {
        return reply(await packPlaintextTo(report, replyKid, replyKey))
      } catch { /* fall through to the HTTP error */ }
    }
    return Response.json({ error: comment, code }, { status })
  }

  class Malformed extends Error {}

  /** Resolves a sender's kid to its key, plus (only for a front-door
   * resolve) the address the published document says it belongs to. An
   * already-bound relationship kid resolves purely from route-store --
   * no network, and no frontDoorAddress (it isn't one). */
  async function resolveSender(senderKid: string): Promise<{ publicKey: Uint8Array; frontDoorAddress?: string }> {
    const boundAddress = routes.addressForRelationshipKid(senderKid)
    if (boundAddress) {
      const holder = routes.holderFor(boundAddress, senderKid)
      if (holder) return { publicKey: holder.pickupPublicKey }
    }
    const resolved = await resolveMailOperationalKid(senderKid)
    if (!resolved) throw new Error(`${senderKid} did not resolve as a mail operational kid`)
    return { publicKey: resolved.publicKey, frontDoorAddress: resolved.address }
  }

  async function unpack(raw: string): Promise<{ msg: DidCommPlaintext; senderKid: string; senderKey: Uint8Array; frontDoorAddress?: string }> {
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

    let resolution: { publicKey: Uint8Array; frontDoorAddress?: string } | undefined
    const { plaintext, senderKid } = await unpackAuthcrypt(jwe, ownRecipient, async kid => {
      resolution = await resolveSender(kid)
      return resolution.publicKey
    })
    return {
      msg: JSON.parse(new TextDecoder().decode(plaintext)), senderKid,
      senderKey: resolution!.publicKey, frontDoorAddress: resolution!.frontDoorAddress,
    }
  }

  async function handle(req: Request, url: URL): Promise<Response | null> {
    if (req.method === 'GET' && url.pathname === '/.well-known/did.json') {
      return Response.json(mediator.doc)
    }
    if (url.pathname !== '/' || req.method !== 'POST') return null

    let msg: DidCommPlaintext
    let senderKid: string
    let senderKey: Uint8Array
    let frontDoorAddress: string | undefined
    try {
      ;({ msg, senderKid, senderKey, frontDoorAddress } = await unpack(await req.text()))
    } catch (e) {
      if (e instanceof Malformed) return Response.json({ error: e.message }, { status: 400 })
      return Response.json({ error: 'could not authenticate this message' }, { status: 401 })
    }

    if (typeof msg.id !== 'string' || !msg.id) {
      return Response.json({ error: 'message has no `id`' }, { status: 400 })
    }
    const fromDid = msg.from
    if (!fromDid) return Response.json({ error: 'message has no `from`' }, { status: 400 })

    if (isExpired(msg)) {
      return problemReply(msg, fromDid, senderKid, senderKey, 400, 'e.p.msg.expired', 'message expired')
    }
    if (!seen.check(msg.id)) {
      return problemReply(msg, fromDid, senderKid, senderKey, 400, 'e.p.crypto.message.dejavu', 'message id {1} already processed', [msg.id])
    }

    try {
      return await dispatch(msg, fromDid, senderKid, senderKey, frontDoorAddress)
    } catch (e) {
      return Response.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 })
    }
  }

  async function dispatch(
    msg: DidCommPlaintext, fromDid: string, senderKid: string, senderKey: Uint8Array, frontDoorAddress: string | undefined,
  ): Promise<Response> {
    switch (msg.type) {
      case ROUTE_BIND: {
        const body = routeBindBodyOf(msg.body)
        if (!body) return Response.json({ error: 'malformed route-bind body' }, { status: 400 })
        // Must have resolved via the front door, for exactly the address
        // it claims -- a relationship kid (frontDoorAddress undefined) or
        // a front-door kid published for a DIFFERENT address are both
        // forged claims, not merely unverified ones.
        if (frontDoorAddress !== body.address) {
          return problemReply(msg, fromDid, senderKid, senderKey, 403, 'e.p.mail.front-door-required', 'route-bind must come from the published mail operational kid for this exact address')
        }
        let route
        try {
          route = transaction(() => routes.bind(body.address, {
            relationshipKid: body.relationshipKid, pickupPublicKey: body.pickupPublicKey, expiresAt: body.expiresAt,
          }, body.routeGeneration, now()))
        } catch (e) {
          if (e instanceof RouteStoreFullError) {
            return problemReply(msg, fromDid, senderKid, senderKey, 503, 'e.p.mail.storage', 'mail mediator is at capacity')
          }
          throw e
        }
        const result: RouteBindResultBody = { address: route.address, routeGeneration: route.routeGeneration, accepted: true }
        return reply(await packReplyTo(msg, fromDid, senderKid, senderKey, ROUTE_BIND_RESULT, result))
      }

      case PICKUP_REQUEST: {
        const address = routes.addressForRelationshipKid(senderKid)
        if (!address) {
          return problemReply(msg, fromDid, senderKid, senderKey, 401, 'e.p.mail.not-bound', 'this kid has no bound route')
        }
        const askedLimit = Number((msg.body as PickupRequestBody | undefined)?.limit ?? 10)
        const limit = Number.isFinite(askedLimit) ? Math.max(1, Math.min(Math.trunc(askedLimit), 100)) : 10
        const claimed = spool.claim(address, senderKid, pickupLeaseMs, limit, now())
        const items = claimed.map(record => ({
          spoolId: record.spoolId, semanticIngressId: record.semanticIngressId,
          mailFrom: record.mailFrom, encryptedBody: record.encryptedBody, bodyHash: record.bodyHash,
          createdAt: record.createdAt,
        }))
        return reply(await packReplyTo(msg, fromDid, senderKid, senderKey, PICKUP, { address, items: items.map(pickupItemToWire) }))
      }

      case MESSAGES_RECEIVED: {
        const address = routes.addressForRelationshipKid(senderKid)
        if (!address) {
          return problemReply(msg, fromDid, senderKid, senderKey, 401, 'e.p.mail.not-bound', 'this kid has no bound route')
        }
        const ackBody = msg.body as MessagesReceivedBody | undefined
        spool.acknowledge(address, senderKid, ackBody?.spoolIds ?? [])
        // Answered with an empty pickup batch rather than a bespoke ack
        // type: PICKUP already carries exactly what a caller needs to know
        // next (anything still pending), mirroring Pickup 3.0's own
        // messages-received -> STATUS precedent.
        return reply(await packReplyTo(msg, fromDid, senderKid, senderKey, PICKUP, { address, items: [] }))
      }

      case SUBMIT: {
        const address = routes.addressForRelationshipKid(senderKid)
        if (!address) {
          return problemReply(msg, fromDid, senderKid, senderKey, 401, 'e.p.mail.not-bound', 'this kid has no bound route')
        }
        const body = submitBodyOf(msg.body)
        if (!body) return Response.json({ error: 'malformed submit body' }, { status: 400 })
        if (body.mailFrom !== address) {
          return problemReply(msg, fromDid, senderKid, senderKey, 403, 'e.p.mail.from-mismatch', "mailFrom does not match this route's address")
        }
        let acquired
        try {
          acquired = submissions.acquire(body.idempotencyKey, body.mailFrom, body.rcptTo, body.rawRfc5322, now())
        } catch (e) {
          if (e instanceof SubmissionStoreFullError) {
            return problemReply(msg, fromDid, senderKid, senderKey, 503, 'e.p.mail.storage', 'mail mediator is at capacity')
          }
          throw e
        }
        if (acquired.started) {
          submitOutbound(acquired.record)
            .then(results => submissions.complete(body.idempotencyKey, results))
            .catch(error => {
              console.error('[mail-mediator] submitOutbound failed:', error)
              submissions.complete(body.idempotencyKey, body.rcptTo.map(recipient => ({
                recipient, status: 'temporary-failure' as const, detail: 'outbound dispatch failed',
              })))
            })
        }
        const result: SubmitResultBody = acquired.record.state === 'completed'
          ? { idempotencyKey: body.idempotencyKey, state: 'completed', results: acquired.record.results }
          : { idempotencyKey: body.idempotencyKey, state: 'in-flight' }
        return reply(await packReplyTo(msg, fromDid, senderKid, senderKey, SUBMIT_RESULT, result))
      }

      case SUBMIT_STATUS_REQUEST: {
        const address = routes.addressForRelationshipKid(senderKid)
        if (!address) {
          return problemReply(msg, fromDid, senderKid, senderKey, 401, 'e.p.mail.not-bound', 'this kid has no bound route')
        }
        const statusBody = msg.body as SubmitStatusRequestBody | undefined
        const record = statusBody?.idempotencyKey ? submissions.recordFor(statusBody.idempotencyKey) : undefined
        // A caller may only poll its OWN submission -- recordFor doesn't
        // know which address asked, so the mailFrom match is the
        // ownership check (mirrors mediator/connections.ts's ownsKey).
        if (!record || record.mailFrom !== address) {
          return problemReply(msg, fromDid, senderKid, senderKey, 404, 'e.p.mail.unknown-submission', 'no such submission for this address')
        }
        const result: SubmitResultBody = record.state === 'completed'
          ? { idempotencyKey: record.idempotencyKey, state: 'completed', results: record.results }
          : { idempotencyKey: record.idempotencyKey, state: 'in-flight' }
        return reply(await packReplyTo(msg, fromDid, senderKid, senderKey, SUBMIT_RESULT, result))
      }

      default:
        return problemReply(msg, fromDid, senderKid, senderKey, 400, 'e.p.msg.not-recognized', 'unrecognized message type {1}', [msg.type])
    }
  }

  return { handle, mediatorDid: mediator.did }
}
