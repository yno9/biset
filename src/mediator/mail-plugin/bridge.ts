// SMTP -> DIDComm bridge: an inbound message accepted for
// `{username}@mail.{apexDomain}` is resolved straight to a Forward-ready
// outbound envelope, with no spool, relationship credential, or VC layer
// (2026-08-30 redesign -- the did:webvh<->mail mapping is already public,
// so there is nothing left to hide from this mediator).
//
// Split into resolve (network -- RCPT TO time, listener.ts's own
// resolveRecipient) and pack (pure -- DATA time, once per accepted
// recipient) so a multi-recipient SMTP transaction resolves each address
// exactly once, at the point core/adapters/mail-smtp-protocol.ts's
// SmtpSession already carries a per-recipient `resolution` from RCPT
// through to acceptIngress (that generic parameter's whole reason for
// existing -- see its own header).
import { fetchRoutingByDomain, type DidCommServiceEndpoint } from '../../didcomm/webvh-routing.ts'
import { decodeX25519Multikey } from '../../didcomm/multikey.ts'
import { buildPlaintext } from '../../didcomm/message.ts'
import { packForDelivery, type OutboundDelivery, type RouteEndpoint } from '../../didcomm/route-deliver.ts'
import { MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyToWire, type MailBridgeInboundBody } from '../../didcomm/mail-bridge.ts'
import { identityDomainForMailAddress } from '../../identity/webvh/identifier.ts'

export interface MailRecipientRoute {
  toAddress: string
  recipientDid: string
  recipientKid: string
  recipientPublicKey: Uint8Array
  endpoint: RouteEndpoint
}

export type ResolveMailRecipientResult = { ok: true; route: MailRecipientRoute } | { ok: false; error: string }

/** Resolves `toAddress`'s routing.json by domain alone (no signed-log
 * resolve, no SCID -- `identityDomainForMailAddress` is the deterministic
 * inverse of `mailFromForIdentity`). What an SMTP listener's RCPT TO
 * handler calls: a `{ ok: false }` here is exactly "no such user" (550). */
export async function resolveMailRecipientRoute(
  toAddress: string,
  apexDomain: string,
  fetchImpl: typeof fetch,
): Promise<ResolveMailRecipientResult> {
  let domain: string
  try {
    domain = identityDomainForMailAddress(toAddress, apexDomain)
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }

  let doc: Awaited<ReturnType<typeof fetchRoutingByDomain>>
  try {
    doc = await fetchRoutingByDomain(domain, fetchImpl)
  } catch (error) {
    return { ok: false, error: `could not resolve ${toAddress}: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (!doc) return { ok: false, error: `${toAddress} does not resolve to a published identity` }

  const service = doc.service.find(s => s.type === 'DIDCommMessaging')
  const serviceEndpoint = service?.serviceEndpoint
  const endpoint = serviceEndpoint && typeof serviceEndpoint === 'object' && !Array.isArray(serviceEndpoint)
    ? (serviceEndpoint as Partial<DidCommServiceEndpoint>)
    : undefined
  if (!endpoint || typeof endpoint.uri !== 'string' || !endpoint.uri) {
    return { ok: false, error: `${toAddress} has no DIDComm service endpoint published` }
  }

  const kaVm = doc.keyAgreementVerificationMethod?.[0]
  if (!kaVm) return { ok: false, error: `${toAddress} has no keyAgreement key published -- they need to enable DIDComm first` }
  let recipientPublicKey: Uint8Array
  try {
    recipientPublicKey = decodeX25519Multikey(kaVm.publicKeyMultibase)
  } catch {
    return { ok: false, error: `${toAddress}'s published keyAgreement key is not a valid X25519 key` }
  }

  return {
    ok: true,
    route: { toAddress, recipientDid: kaVm.controller, recipientKid: kaVm.id, recipientPublicKey, endpoint: { uri: endpoint.uri, routingKeys: endpoint.routingKeys } },
  }
}

/** Pure (no network): authcrypts a MAIL_BRIDGE_INBOUND message to an
 * already-resolved recipient route -- `sender` identifies this bridge (a
 * persisted did:peer, `SqliteMediatorStore.loadMailPluginIdentity`, kept
 * separate from a real end-user's DIDComm identity, but present because the
 * client's existing mediator-polling pipeline unpacks every queued item as
 * authcrypt (mediator-pickup.ts's `pickupDeliver`) -- an anoncrypt payload
 * would never decode there). Forward-wraps through the recipient's full hop
 * chain when they published one (didcomm/route-deliver.ts). Throws if the
 * route's own routing keys are malformed -- a listener has already resolved
 * the route once by the time it calls this, so that should not happen in
 * practice, but a caller distrusting a stale/cached route should catch it. */
export function packInboundMailForward(
  route: MailRecipientRoute,
  body: MailBridgeInboundBody,
  sender: { kid: string; privateKey: Uint8Array },
): OutboundDelivery {
  const plaintext = buildPlaintext(MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyToWire(body), sender.kid.split('#', 1)[0], route.recipientDid)
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext))
  return packForDelivery(plaintextBytes, sender, route.recipientKid, route.recipientPublicKey, route.endpoint)
}

export type MailBridgeResult = { ok: true; delivery: OutboundDelivery } | { ok: false; error: string }

/** Convenience one-shot: resolve then pack in a single call, for a direct
 * caller that has no reason to resolve ahead of time (tests, a one-off
 * script). The SMTP listener itself calls `resolveMailRecipientRoute` and
 * `packInboundMailForward` separately instead, so RCPT-time resolution and
 * DATA-time packing don't each redo the same routing.json fetch. */
export async function buildInboundMailForward(
  toAddress: string,
  apexDomain: string,
  body: MailBridgeInboundBody,
  sender: { kid: string; privateKey: Uint8Array },
  fetchImpl: typeof fetch,
): Promise<MailBridgeResult> {
  const resolved = await resolveMailRecipientRoute(toAddress, apexDomain, fetchImpl)
  if (!resolved.ok) return resolved
  try {
    return { ok: true, delivery: packInboundMailForward(resolved.route, body, sender) }
  } catch (error) {
    return { ok: false, error: `${toAddress}'s registered mediator routing keys are invalid: ${error instanceof Error ? error.message : String(error)}` }
  }
}
