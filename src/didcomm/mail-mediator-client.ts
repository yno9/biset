// Mail Mediator client transport: route-bind, pickup-request,
// messages-received, submit, submit-status-request
// (PLAN_biset-mail-mediator.md section 4). Reuses mediator-transport.ts's
// fetchMediatorInfo/sendAndUnpack verbatim -- a Mail Mediator's did:peer
// document and synchronous authcrypt request/reply shape is identical to
// the DIDComm mediator's own (src/mail-mediator/server.ts serves the same
// `.well-known/did.json` + POST / shape on purpose), so there is no
// separate transport to write, only the message types differ.
import { sendAndUnpack, type DidCommSender, type MediatorInfo } from './mediator-transport.ts'
import { defaultFetch } from '../net-fetch.ts'
import {
  ROUTE_BIND, ROUTE_BIND_RESULT, PICKUP_REQUEST, PICKUP, MESSAGES_RECEIVED, SUBMIT, SUBMIT_STATUS_REQUEST, SUBMIT_RESULT,
  routeBindBodyToWire, pickupItemOf, submitBodyToWire,
  type RouteBindBody, type RouteBindResultBody, type PickupItem, type PickupItemWire,
  type SubmitBody, type SubmitResultBody,
} from '../mail-mediator/protocol.ts'

/** Sends route-bind authcrypt'd from the address's PUBLIC front-door
 * kid (`frontDoor` -- the identity-shared didCommKid). Throws (via
 * sendAndUnpack's DidCommProblemError) if the mediator refuses the bind,
 * e.g. `e.p.mail.front-door-required` for a stale/mismatched claim. */
export async function bindMailRoute(
  mediator: MediatorInfo, frontDoor: DidCommSender, body: RouteBindBody, fetchImpl: typeof fetch = defaultFetch(),
): Promise<RouteBindResultBody> {
  const reply = await sendAndUnpack(mediator, frontDoor, ROUTE_BIND, routeBindBodyToWire(body), fetchImpl)
  if (reply.type !== ROUTE_BIND_RESULT) throw new Error(`bindMailRoute: unexpected reply type ${reply.type}`)
  return reply.body as RouteBindResultBody
}

/** Every call below is authcrypt'd from the bound RELATIONSHIP identity,
 * never the front-door one -- passing `frontDoor` here is refused by the
 * mediator (server.ts's own front-door/relationship-kid split). */
export async function pickupMail(
  mediator: MediatorInfo, relationship: DidCommSender, limit = 10, fetchImpl: typeof fetch = defaultFetch(),
): Promise<{ address: string; items: PickupItem[] }> {
  const reply = await sendAndUnpack(mediator, relationship, PICKUP_REQUEST, { limit }, fetchImpl)
  if (reply.type !== PICKUP) throw new Error(`pickupMail: unexpected reply type ${reply.type}`)
  const body = reply.body as { address: string; items: PickupItemWire[] }
  return { address: body.address, items: body.items.map(pickupItemOf) }
}

/** Confirms durable local commit of the named spool ids so the mediator
 * may drop them (PLAN section 7 -- non-destructive pickup until this
 * ACK). No-op for an empty list. */
export async function acknowledgeMail(
  mediator: MediatorInfo, relationship: DidCommSender, address: string, spoolIds: string[], fetchImpl: typeof fetch = defaultFetch(),
): Promise<void> {
  if (spoolIds.length === 0) return
  const reply = await sendAndUnpack(mediator, relationship, MESSAGES_RECEIVED, { address, spoolIds }, fetchImpl)
  if (reply.type !== PICKUP) throw new Error(`acknowledgeMail: unexpected reply type ${reply.type}`)
}

/** Submits an already-locally-committed outbound message. Always returns
 * `state: 'in-flight'` on success -- the async model means the actual
 * per-recipient result is fetched later via submitMailStatus (PLAN
 * section 12, revised). */
export async function submitMail(
  mediator: MediatorInfo, relationship: DidCommSender, body: SubmitBody, fetchImpl: typeof fetch = defaultFetch(),
): Promise<SubmitResultBody> {
  const reply = await sendAndUnpack(mediator, relationship, SUBMIT, submitBodyToWire(body), fetchImpl)
  if (reply.type !== SUBMIT_RESULT) throw new Error(`submitMail: unexpected reply type ${reply.type}`)
  return reply.body as SubmitResultBody
}

export async function submitMailStatus(
  mediator: MediatorInfo, relationship: DidCommSender, idempotencyKey: string, fetchImpl: typeof fetch = defaultFetch(),
): Promise<SubmitResultBody> {
  const reply = await sendAndUnpack(mediator, relationship, SUBMIT_STATUS_REQUEST, { idempotencyKey }, fetchImpl)
  if (reply.type !== SUBMIT_RESULT) throw new Error(`submitMailStatus: unexpected reply type ${reply.type}`)
  return reply.body as SubmitResultBody
}
