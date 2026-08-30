// SMTP -> DIDComm bridge: an inbound message accepted for
// `{username}@mail.{apexDomain}` is resolved straight to a Forward-ready
// outbound envelope, with no spool, relationship credential, or VC layer
// (2026-08-30 redesign -- the did:webvh<->mail mapping is already public,
// so there is nothing left to hide from this mediator). This module only
// builds the envelope; the SMTP listener that calls it and the HTTP POST
// that delivers it are separate, not yet built (mediator/mail-plugin/ is
// currently just this one function plus its identity, index.ts wiring is
// still to come).
import { fetchRoutingByDomain, type DidCommServiceEndpoint } from '../../didcomm/webvh-routing.ts'
import { decodeX25519Multikey } from '../../didcomm/multikey.ts'
import { buildPlaintext } from '../../didcomm/message.ts'
import { packForDelivery, type OutboundDelivery } from '../../didcomm/route-deliver.ts'
import { MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyToWire, type MailBridgeInboundBody } from '../../didcomm/mail-bridge.ts'
import { identityDomainForMailAddress } from '../../identity/webvh/identifier.ts'

export type MailBridgeResult = { ok: true; delivery: OutboundDelivery } | { ok: false; error: string }

/** Resolves `toAddress`'s routing.json by domain alone (no signed-log
 * resolve, no SCID) and authcrypts a MAIL_BRIDGE_INBOUND message to its
 * published keyAgreement key -- `sender` identifies this bridge (a
 * persisted did:peer, `SqliteMediatorStore.loadMailPluginIdentity`, kept
 * separate from a real end-user's DIDComm identity, but present because the
 * client's existing mediator-polling pipeline unpacks every queued item as
 * authcrypt (mediator-pickup.ts's `pickupDeliver`) -- an anoncrypt payload
 * would never decode there). Forward-wraps through the recipient's full
 * hop chain when they published one (didcomm/route-deliver.ts). */
export async function buildInboundMailForward(
  toAddress: string,
  apexDomain: string,
  body: MailBridgeInboundBody,
  sender: { kid: string; privateKey: Uint8Array },
  fetchImpl: typeof fetch,
): Promise<MailBridgeResult> {
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

  const plaintext = buildPlaintext(MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyToWire(body), sender.kid.split('#', 1)[0], kaVm.controller)
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext))

  try {
    const delivery = packForDelivery(plaintextBytes, sender, kaVm.id, recipientPublicKey, { uri: endpoint.uri, routingKeys: endpoint.routingKeys })
    return { ok: true, delivery }
  } catch (error) {
    return { ok: false, error: `${toAddress}'s registered mediator routing keys are invalid: ${error instanceof Error ? error.message : String(error)}` }
  }
}
