// Establishes (once) and returns this identity's per-mail-mediator
// relationship credential (PLAN_biset-mail-mediator.md section 4, revised
// to a VC-based route-bind). Mirrors identity/bootstrap.ts's enableDidComm
// shape: idempotent (a credential already synced from a sibling device
// via readCurrentFor short-circuits this), best-effort by design (the
// caller wraps this in a .catch, same treatment as
// enableDidComm/enableOpenPgpMail).
//
// Route-bind no longer authcrypts from a front-door kid at all -- it is
// sent from the FRESH relationship identity itself, carrying a
// BisetMailAddressOwnershipCredential Anchor just issued for it
// (requestMailAddressCredential). The mediator never learns this
// identity's own did:webvh.
import { generatePeerIdentity } from '../didcomm/peer.ts'
import { fetchMediatorInfo, type DidCommSender } from '../didcomm/mediator-transport.ts'
import { bindMailRoute } from '../didcomm/mail-mediator-client.ts'
import { requestMailAddressCredential } from '../oid4vp/mail-address-client.ts'
import type { MailRelationshipCredentialReader } from '../vault/mail-relationship-credential-reader.ts'
import type { MailRelationshipCredentialVaultSink } from '../vault/mail-relationship-credential-sink.ts'
import type { MailRelationshipCredentialV1 } from '../vault/mail-relationship-credential.ts'
import { defaultFetch } from '../net-fetch.ts'

const ROUTE_TTL_MS = 90 * 24 * 60 * 60 * 1000

export async function ensureMailRelationship(
  reader: MailRelationshipCredentialReader,
  sink: MailRelationshipCredentialVaultSink,
  /** This identity's own stable did:webvh -- used ONLY to ask Anchor for
   * the mail address credential (Anchor already knows this identity's
   * DID from its own login session; this is what proves this specific
   * relationship key belongs to it). Never sent to the mediator. */
  identityDid: string,
  address: string,
  mediatorUrl: string,
  anchorBaseUrl: string,
  fetchImpl: typeof fetch = defaultFetch(),
): Promise<MailRelationshipCredentialV1> {
  const existing = await reader.readCurrentFor(mediatorUrl)
  if (existing) return existing

  const relationshipPeer = generatePeerIdentity()
  const relationshipSender: DidCommSender = { did: relationshipPeer.did, xKid: relationshipPeer.xKid, xPriv: relationshipPeer.xPriv }
  const mailAddressCredential = await requestMailAddressCredential({
    anchorBaseUrl, did: identityDid, relationshipDid: relationshipPeer.did,
    relationshipEdPrivateKey: relationshipPeer.edPriv, fetch: fetchImpl,
  })
  const mediator = await fetchMediatorInfo(mediatorUrl, fetchImpl)
  const routeGeneration = crypto.randomUUID()
  const expiresAt = new Date(Date.now() + ROUTE_TTL_MS).toISOString()
  await bindMailRoute(mediator, relationshipSender, {
    address, relationshipKid: relationshipPeer.xKid, pickupPublicKey: relationshipPeer.xPub,
    routeGeneration, expiresAt, mailAddressCredential: mailAddressCredential.credential,
  }, fetchImpl)

  const credential: MailRelationshipCredentialV1 = {
    version: 1, kind: 'credential.mail-relationship', identityId: identityDid,
    mediatorUrl, address, relationshipDid: relationshipPeer.did,
    privateKey: relationshipPeer.xPriv, edPrivateKey: relationshipPeer.edPriv,
    routeGeneration, createdAt: new Date().toISOString(),
  }
  await sink.store(credential)
  return credential
}
