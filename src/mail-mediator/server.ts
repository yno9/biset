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
// Every message here, INCLUDING route-bind, authcrypts from the
// RELATIONSHIP identity itself (a did:peer:2, self-certifying) --
// there is no front-door tier any more. Authorization for route-bind
// comes from a BisetMailAddressOwnershipCredential
// (src/oid4vp/mail-address-profile.ts) carried in its body: Anchor's
// signature proves `address` belongs to `cnf.relationshipDid`, and this
// dispatch checks that `cnf.relationshipDid` against
// `didOfKid(senderKid)` -- the DID the authcrypt envelope was actually
// sent from. This mediator therefore never resolves a did:webvh document
// or learns the identity's own DID at any point (the earlier
// resolveMailOperationalKid design did, at bind time only -- this
// removes even that).
import { decodePeerDid2, publicKeyOf, type PeerIdentity } from '../didcomm/peer.ts'
import { buildPlaintext, isExpired, type DidCommPlaintext } from '../didcomm/message.ts'
import { buildProblemReport } from '../didcomm/problems.ts'
import { packAuthcrypt, unpackAuthcrypt, parseJwe, protectedHeaderOf } from '../didcomm/crypto.ts'
import { didOfKid } from '../protocol/ids.ts'
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
import { ContactHistoryStore, type MailContactHistoryStore } from './contact-history-store.ts'

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
  /** Verifies a BisetMailAddressOwnershipCredential JWT (Anchor's
   * signature, validity window, claim shape) and returns its claims.
   * Throws on any failure -- there is no "null means unverifiable" case,
   * unlike the old resolveMailOperationalKid, since this never needs a
   * network resolve (Anchor's signing key is a fixed, injected value).
   * Kept as an injected function rather than importing
   * verifyBisetMailAddressCredential directly so this module still has
   * no import from `oid4vp/` at the type level -- only the caller
   * (index.ts) wires that dependency in. */
  verifyMailAddressCredential: (token: string, now: string) => { address: string; relationshipDid: string }
  /** Actually dials SMTP for an acquired submission and returns each
   * recipient's outcome. Invoked fire-and-forget from the `submit`
   * handler (async model -- PLAN section 12, revised): the client polls
   * `submit-status-request` for the result instead of blocking the
   * `submit` round trip on SMTP dialogue. A throw is treated as a
   * temporary-failure for every recipient, never left permanently
   * in-flight. */
  submitOutbound: (record: SubmissionRecord) => Promise<RecipientResult[]>
  /** Outbound recipient allowlist (revised PLAN section 12): a `submit`
   * recipient must be under one of these domains, or already a known
   * contact (contactHistory.hasContact, populated by DKIM-verified
   * inbound mail -- smtp-listener.ts). Empty/omitted keeps today's exact
   * behavior (no recipient restriction at all). */
  allowedRecipientDomains?: string[]
  contactHistory?: MailContactHistoryStore
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
  verifyMailAddressCredential,
  submitOutbound,
  allowedRecipientDomains = [],
  contactHistory = new ContactHistoryStore(),
  now = () => new Date().toISOString(),
  pickupLeaseMs = DEFAULT_PICKUP_LEASE_MS,
}: MailMediatorOptions): MailMediatorHandler {
  const normalizedAllowedDomains = allowedRecipientDomains.map(d => d.toLowerCase())

  /** No restriction configured at all keeps today's exact behavior (any
   * recipient). Otherwise a recipient must be under an allowed domain,
   * or already a known contact of the SENDING address (one-directional
   * trust -- see contact-history-store.ts's own header). */
  function isAllowedRecipient(senderAddress: string, recipient: string): boolean {
    if (normalizedAllowedDomains.length === 0) return true
    const domain = recipient.split('@')[1]?.toLowerCase()
    if (domain && normalizedAllowedDomains.some(allowed => domain === allowed || domain.endsWith(`.${allowed}`))) return true
    return contactHistory.hasContact(senderAddress, recipient)
  }
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

  /** did:peer:2 is self-certifying -- the sender's public key is decoded
   * straight out of its own DID, no network resolve of any kind. This is
   * the ONLY resolution path now: there is no front-door tier left to
   * fall back to. */
  function resolveSenderKey(senderKid: string): Uint8Array {
    const did = didOfKid(senderKid)
    if (!did.startsWith('did:peer:2.')) throw new Error(`${senderKid} is not a did:peer:2 kid`)
    return publicKeyOf(decodePeerDid2(did), senderKid)
  }

  async function unpack(raw: string): Promise<{ msg: DidCommPlaintext; senderKid: string; senderKey: Uint8Array }> {
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

    const { plaintext, senderKid } = await unpackAuthcrypt(jwe, ownRecipient, kid => resolveSenderKey(kid))
    return { msg: JSON.parse(new TextDecoder().decode(plaintext)), senderKid, senderKey: resolveSenderKey(senderKid) }
  }

  async function handle(req: Request, url: URL): Promise<Response | null> {
    if (req.method === 'GET' && url.pathname === '/.well-known/did.json') {
      return Response.json(mediator.doc)
    }
    if (url.pathname !== '/' || req.method !== 'POST') return null

    let msg: DidCommPlaintext
    let senderKid: string
    let senderKey: Uint8Array
    try {
      ;({ msg, senderKid, senderKey } = await unpack(await req.text()))
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
      return await dispatch(msg, fromDid, senderKid, senderKey)
    } catch (e) {
      return Response.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 })
    }
  }

  async function dispatch(msg: DidCommPlaintext, fromDid: string, senderKid: string, senderKey: Uint8Array): Promise<Response> {
    switch (msg.type) {
      case ROUTE_BIND: {
        const body = routeBindBodyOf(msg.body)
        if (!body) return Response.json({ error: 'malformed route-bind body' }, { status: 400 })
        let vc: { address: string; relationshipDid: string }
        try {
          vc = verifyMailAddressCredential(body.mailAddressCredential, now())
        } catch (e) {
          return problemReply(msg, fromDid, senderKid, senderKey, 403, 'e.p.mail.credential-invalid', e instanceof Error ? e.message : 'mail address credential is invalid')
        }
        // Both checks matter independently: the VC's address must match
        // what THIS request claims (a stale VC for a since-rotated
        // address must not silently bind the wrong route), and the VC's
        // relationshipDid must match who actually sent THIS message (a
        // VC minted for one relationship can't authorize a bind on
        // another's behalf, even if somehow relayed).
        if (vc.address !== body.address || vc.relationshipDid !== didOfKid(senderKid)) {
          return problemReply(msg, fromDid, senderKid, senderKey, 403, 'e.p.mail.credential-mismatch', 'mail address credential does not match this request')
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
        // Recipient-unit, not a whole-request reject (PLAN section 12's
        // own "複数recipientの部分成功を単一booleanへ潰さない" rule):
        // a disallowed recipient is reported back as permanent-failure
        // for THAT address, while allowed ones still go out.
        const allowedRecipients = body.rcptTo.filter(r => isAllowedRecipient(address, r))
        const disallowedRecipients = body.rcptTo.filter(r => !isAllowedRecipient(address, r))
        if (allowedRecipients.length === 0) {
          return problemReply(msg, fromDid, senderKid, senderKey, 403, 'e.p.mail.recipient-not-allowed', 'no recipient is allowed for this address')
        }
        let acquired
        try {
          acquired = submissions.acquire(body.idempotencyKey, body.mailFrom, allowedRecipients, body.rawRfc5322, now())
        } catch (e) {
          if (e instanceof SubmissionStoreFullError) {
            return problemReply(msg, fromDid, senderKid, senderKey, 503, 'e.p.mail.storage', 'mail mediator is at capacity')
          }
          throw e
        }
        const disallowedResults: RecipientResult[] = disallowedRecipients.map(recipient => (
          { recipient, status: 'permanent-failure', detail: 'recipient not allowed' }
        ))
        if (acquired.started) {
          submitOutbound(acquired.record)
            .then(results => submissions.complete(body.idempotencyKey, [...results, ...disallowedResults]))
            .catch(error => {
              console.error('[mail-mediator] submitOutbound failed:', error)
              submissions.complete(body.idempotencyKey, [
                ...allowedRecipients.map(recipient => ({ recipient, status: 'temporary-failure' as const, detail: 'outbound dispatch failed' })),
                ...disallowedResults,
              ])
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
