// Private, per-mail-mediator relationship credential -- same identity-shared
// pattern as vault/didcomm-credential.ts, except keyed by mediatorUrl
// instead of being identity-wide singleton: PLAN_biset-mail-mediator.md
// section 4's relationship kid is deliberately a fresh, mediator-specific
// identity (a did:peer:2, generated client-side) that this mail mediator
// never learns is connected to the identity's public front-door kid --
// unlike the DIDComm mediator's shared didCommKid, there is exactly one
// relationship credential per mediator this identity has bound a route
// with, not one for the whole identity.
import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../protocol/canonical.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import { createVaultEvent, type VaultEventSigner } from './events.ts'
import { encryptVaultObject } from './objects.ts'

export interface MailRelationshipCredentialV1 {
  version: 1
  kind: 'credential.mail-relationship'
  identityId: IdentityId
  /** The Mail Mediator this relationship was bound with. */
  mediatorUrl: string
  /** The address this relationship is for (route-store.ts's own key). */
  address: string
  /** This relationship's did:peer:2 identity -- self-certifying, never
   * resolved against the identity's own public did:webvh document. */
  relationshipDid: string
  /** 32-byte X25519 scalar for `relationshipDid`'s keyAgreement key. */
  privateKey: Uint8Array
  /** 32-byte Ed25519 scalar for `relationshipDid`'s authentication key
   * (did:peer:2 needs both to decode/encode the DID string itself). */
  edPrivateKey: Uint8Array
  routeGeneration: string
  createdAt: string
  supersedesRelationshipDid?: string
}

export interface MailRelationshipCredentialBuildContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: SegmentId
  segmentKey: Uint8Array
}

export interface MailRelationshipCredentialRecord {
  credential: MailRelationshipCredentialV1
  object: VaultObjectV1
  event: VaultEventV1
}

export function encodeMailRelationshipCredential(value: MailRelationshipCredentialV1): Uint8Array {
  assertCredential(value)
  return canonicalBytes({
    version: value.version,
    kind: value.kind,
    identityId: value.identityId,
    mediatorUrl: value.mediatorUrl,
    address: value.address,
    relationshipDid: value.relationshipDid,
    privateKey: bytesToBase64url(value.privateKey),
    edPrivateKey: bytesToBase64url(value.edPrivateKey),
    routeGeneration: value.routeGeneration,
    createdAt: value.createdAt,
    ...(value.supersedesRelationshipDid === undefined ? {} : { supersedesRelationshipDid: value.supersedesRelationshipDid }),
  })
}

export function decodeMailRelationshipCredential(bytes: Uint8Array): MailRelationshipCredentialV1 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('mail relationship credential is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('mail relationship credential must be an object')
  const value = input as Record<string, unknown>
  if (
    value.version !== 1 || value.kind !== 'credential.mail-relationship' ||
    typeof value.identityId !== 'string' || typeof value.mediatorUrl !== 'string' || typeof value.address !== 'string' ||
    typeof value.relationshipDid !== 'string' || typeof value.privateKey !== 'string' || typeof value.edPrivateKey !== 'string' ||
    typeof value.routeGeneration !== 'string' || typeof value.createdAt !== 'string' ||
    (value.supersedesRelationshipDid !== undefined && typeof value.supersedesRelationshipDid !== 'string')
  ) throw new TypeError('mail relationship credential shape is invalid')
  const credential: MailRelationshipCredentialV1 = {
    version: 1, kind: 'credential.mail-relationship', identityId: value.identityId, mediatorUrl: value.mediatorUrl,
    address: value.address, relationshipDid: value.relationshipDid,
    privateKey: base64urlToBytes(value.privateKey), edPrivateKey: base64urlToBytes(value.edPrivateKey),
    routeGeneration: value.routeGeneration, createdAt: value.createdAt,
    ...(value.supersedesRelationshipDid === undefined ? {} : { supersedesRelationshipDid: value.supersedesRelationshipDid }),
  }
  if (!equalBytes(bytes, encodeMailRelationshipCredential(credential))) throw new TypeError('mail relationship credential is not canonical')
  return credential
}

export async function buildMailRelationshipCredential(
  credential: MailRelationshipCredentialV1,
  context: MailRelationshipCredentialBuildContext,
  signer: VaultEventSigner,
): Promise<MailRelationshipCredentialRecord> {
  assertCredential(credential)
  if (context.identityId !== credential.identityId || context.actorDeviceId !== signer.deviceId || !context.segmentId || context.segmentKey.length !== 32) {
    throw new TypeError('mail relationship credential build context is invalid')
  }
  const object = await encryptVaultObject(context.segmentKey, {
    segmentId: context.segmentId,
    plaintext: encodeMailRelationshipCredential(credential),
    aad: mailRelationshipCredentialAad(context.identityId, context.segmentId, credential.mediatorUrl, credential.relationshipDid),
  })
  const event = await createVaultEvent({
    identityId: context.identityId,
    actorDeviceId: context.actorDeviceId,
    actorSeq: context.actorSeq,
    kind: 'credential.mail-relationship.set',
    targetIds: [`mail-relationship:${credential.mediatorUrl}:${credential.relationshipDid}`],
    objectRefs: [object.objectId],
    parents: [...context.parents],
    createdAt: credential.createdAt,
  }, signer)
  return { credential: copyCredential(credential), object, event }
}

export function mailRelationshipCredentialAad(identityId: IdentityId, segmentId: SegmentId, mediatorUrl: string, relationshipDid: string): Uint8Array {
  return canonicalBytes({ label: 'biset/vault/credential/mail-relationship/aad/v1', identityId, segmentId, mediatorUrl, relationshipDid })
}

export function assertMailRelationshipCredentialRecord(event: VaultEventV1, object: VaultObjectV1, plaintext: Uint8Array): MailRelationshipCredentialV1 {
  if (event.kind !== 'credential.mail-relationship.set' || event.objectRefs.length !== 1 || event.objectRefs[0] !== object.objectId) {
    throw new TypeError('mail relationship credential event does not reference its object')
  }
  const credential = decodeMailRelationshipCredential(plaintext)
  if (
    credential.identityId !== event.identityId || credential.createdAt !== event.createdAt ||
    event.targetIds.length !== 1 || event.targetIds[0] !== `mail-relationship:${credential.mediatorUrl}:${credential.relationshipDid}` ||
    !equalBytes(object.aad, mailRelationshipCredentialAad(credential.identityId, object.segmentId, credential.mediatorUrl, credential.relationshipDid))
  ) {
    throw new TypeError('mail relationship credential record metadata does not match')
  }
  return credential
}

function assertCredential(value: MailRelationshipCredentialV1): void {
  if (!value.identityId || value.kind !== 'credential.mail-relationship' || !value.mediatorUrl || !value.address) {
    throw new TypeError('mail relationship credential is invalid')
  }
  if (value.privateKey.length !== 32 || value.edPrivateKey.length !== 32 || Number.isNaN(Date.parse(value.createdAt))) {
    throw new TypeError('mail relationship credential is invalid')
  }
  if (value.supersedesRelationshipDid !== undefined && value.supersedesRelationshipDid === value.relationshipDid) {
    throw new TypeError('mail relationship credential cannot supersede itself')
  }
}

function copyCredential(value: MailRelationshipCredentialV1): MailRelationshipCredentialV1 {
  return { ...value, privateKey: value.privateKey.slice(), edPrivateKey: value.edPrivateKey.slice() }
}
