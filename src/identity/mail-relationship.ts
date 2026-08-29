// Establishes (once) and returns this identity's per-mail-mediator
// relationship credential (PLAN_biset-mail-mediator.md section 4). Mirrors
// identity/bootstrap.ts's enableDidComm shape: idempotent (a credential
// already synced from a sibling device via readCurrentFor short-circuits
// this), best-effort by design (the caller wraps this in a .catch, same
// treatment as enableDidComm/enableOpenPgpMail).
import { generatePeerIdentity } from '../didcomm/peer.ts'
import { fetchMediatorInfo, type DidCommSender } from '../didcomm/mediator-transport.ts'
import { bindMailRoute } from '../didcomm/mail-mediator-client.ts'
import type { MailRelationshipCredentialReader } from '../vault/mail-relationship-credential-reader.ts'
import type { MailRelationshipCredentialVaultSink } from '../vault/mail-relationship-credential-sink.ts'
import type { MailRelationshipCredentialV1 } from '../vault/mail-relationship-credential.ts'
import { defaultFetch } from '../net-fetch.ts'

const ROUTE_TTL_MS = 90 * 24 * 60 * 60 * 1000

export async function ensureMailRelationship(
  reader: MailRelationshipCredentialReader,
  sink: MailRelationshipCredentialVaultSink,
  frontDoor: DidCommSender,
  address: string,
  mediatorUrl: string,
  fetchImpl: typeof fetch = defaultFetch(),
): Promise<MailRelationshipCredentialV1> {
  const existing = await reader.readCurrentFor(mediatorUrl)
  if (existing) return existing

  const relationshipPeer = generatePeerIdentity()
  const mediator = await fetchMediatorInfo(mediatorUrl, fetchImpl)
  const routeGeneration = crypto.randomUUID()
  const expiresAt = new Date(Date.now() + ROUTE_TTL_MS).toISOString()
  await bindMailRoute(mediator, frontDoor, {
    address, relationshipKid: relationshipPeer.xKid, pickupPublicKey: relationshipPeer.xPub,
    routeGeneration, expiresAt,
  }, fetchImpl)

  const credential: MailRelationshipCredentialV1 = {
    version: 1, kind: 'credential.mail-relationship', identityId: frontDoor.did,
    mediatorUrl, address, relationshipDid: relationshipPeer.did,
    privateKey: relationshipPeer.xPriv, edPrivateKey: relationshipPeer.edPriv,
    routeGeneration, createdAt: new Date().toISOString(),
  }
  await sink.store(credential)
  return credential
}
