import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../../../protocol/canonical.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../../../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../../../protocol/vault.ts'
import { decodePeerDid2, encodePeerDid2, publicKeyOf } from '../../../protocol/didcomm/peer.ts'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { createVaultEvent, type VaultEventAuthor } from './events.ts'
import { encryptVaultObject } from './objects.ts'
import type { VaultCredentialKind } from './credential-store.ts'
import type { VaultCredentialEventReader } from './store.ts'

/**
 * One private, identity-wide relationship credential. The public DIDComm
 * identity is a self-certifying did:peer:2 value; only this encrypted vault
 * record links it to either participant's public did:webvh identity.
 */
export interface ContactKeyV1 {
  version: 1
  kind: 'contact-key'
  identityId: IdentityId
  counterpartyDid: string
  ownRelationshipKid: string
  ownX25519PrivateKey: Uint8Array
  ownEd25519PrivateKey: Uint8Array
  counterpartyRelationshipKid: string
  counterpartyPublicKey: Uint8Array
  createdAt: string
  /** The relationship seed this side's own did:peer was derived from
   * (relationship-seed.ts). A record from an older seed is a relationship
   * that has not moved yet since a device removal. */
  seedId: string
  /** The relationship this record replaces: either side moved to a new
   * did:peer (a device removal), announced by a front-door INIT. A
   * relationship is named by BOTH kids, since either side can move without
   * the other. */
  supersedes?: ContactKeyRef
}

/** Names one relationship: the pair of did:peer kids it runs between. */
export interface ContactKeyRef { ownRelationshipKid: string; counterpartyRelationshipKid: string }

export function contactKeyRef(value: ContactKeyRef): string {
  return `${value.ownRelationshipKid} ${value.counterpartyRelationshipKid}`
}

export interface ContactKeyBuildContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: SegmentId
  segmentKey: Uint8Array
}

export interface ContactKeyRecord {
  contactKey: ContactKeyV1
  object: VaultObjectV1
  event: VaultEventV1
}

function encodeContactKey(value: ContactKeyV1): Uint8Array {
  assertContactKey(value)
  return canonicalBytes({
    version: value.version,
    kind: value.kind,
    identityId: value.identityId,
    counterpartyDid: value.counterpartyDid,
    ownRelationshipKid: value.ownRelationshipKid,
    ownX25519PrivateKey: bytesToBase64url(value.ownX25519PrivateKey),
    ownEd25519PrivateKey: bytesToBase64url(value.ownEd25519PrivateKey),
    counterpartyRelationshipKid: value.counterpartyRelationshipKid,
    counterpartyPublicKey: bytesToBase64url(value.counterpartyPublicKey),
    createdAt: value.createdAt,
    seedId: value.seedId,
    ...(value.supersedes === undefined ? {} : { supersedes: { ownRelationshipKid: value.supersedes.ownRelationshipKid, counterpartyRelationshipKid: value.supersedes.counterpartyRelationshipKid } }),
  })
}

function refOf(value: unknown): ContactKeyRef | undefined {
  if (value === undefined) return undefined
  const ref = value as Record<string, unknown> | null
  if (!ref || typeof ref !== 'object' || typeof ref.ownRelationshipKid !== 'string' || typeof ref.counterpartyRelationshipKid !== 'string' || Object.keys(ref).length !== 2) {
    throw new TypeError('contact key shape is invalid')
  }
  return { ownRelationshipKid: ref.ownRelationshipKid, counterpartyRelationshipKid: ref.counterpartyRelationshipKid }
}

export function decodeContactKey(bytes: Uint8Array): ContactKeyV1 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('contact key is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('contact key must be an object')
  const value = input as Record<string, unknown>
  if (
    value.version !== 1 || value.kind !== 'contact-key' ||
    typeof value.identityId !== 'string' || typeof value.counterpartyDid !== 'string' ||
    typeof value.ownRelationshipKid !== 'string' || typeof value.ownX25519PrivateKey !== 'string' ||
    typeof value.ownEd25519PrivateKey !== 'string' || typeof value.counterpartyRelationshipKid !== 'string' ||
    typeof value.counterpartyPublicKey !== 'string' || typeof value.createdAt !== 'string' ||
    typeof value.seedId !== 'string'
  ) throw new TypeError('contact key shape is invalid')
  const supersedes = refOf(value.supersedes)
  const contactKey: ContactKeyV1 = {
    version: 1,
    kind: 'contact-key',
    identityId: value.identityId,
    counterpartyDid: value.counterpartyDid,
    ownRelationshipKid: value.ownRelationshipKid,
    ownX25519PrivateKey: base64urlToBytes(value.ownX25519PrivateKey),
    ownEd25519PrivateKey: base64urlToBytes(value.ownEd25519PrivateKey),
    counterpartyRelationshipKid: value.counterpartyRelationshipKid,
    counterpartyPublicKey: base64urlToBytes(value.counterpartyPublicKey),
    createdAt: value.createdAt,
    seedId: value.seedId,
    ...(supersedes === undefined ? {} : { supersedes }),
  }
  if (!equalBytes(bytes, encodeContactKey(contactKey))) throw new TypeError('contact key is not canonical')
  return contactKey
}

export async function buildContactKeyRecord(
  contactKey: ContactKeyV1,
  context: ContactKeyBuildContext,
  signer: VaultEventAuthor,
): Promise<ContactKeyRecord> {
  assertContactKey(contactKey)
  if (context.identityId !== contactKey.identityId || context.actorDeviceId !== signer.deviceId || !context.segmentId || context.segmentKey.length !== 32) {
    throw new TypeError('contact key build context is invalid')
  }
  const object = await encryptVaultObject(context.segmentKey, {
    segmentId: context.segmentId,
    plaintext: encodeContactKey(contactKey),
    aad: contactKeyAad(context.identityId, context.segmentId, contactKey.counterpartyDid, contactKey),
  })
  const event = await createVaultEvent({
    identityId: context.identityId,
    actorDeviceId: context.actorDeviceId,
    actorSeq: context.actorSeq,
    kind: 'contact-key.set',
    targetIds: [contactKeyTarget(contactKey.counterpartyDid, contactKey)],
    objectRefs: [object.objectId],
    parents: [...context.parents],
    createdAt: contactKey.createdAt,
  }, signer)
  return { contactKey: copyContactKey(contactKey), object, event }
}

function contactKeyTarget(counterpartyDid: string, ref: ContactKeyRef): string {
  if (!counterpartyDid || !ref.ownRelationshipKid || !ref.counterpartyRelationshipKid) throw new TypeError('contact key target is invalid')
  return `contact-key:${counterpartyDid}:${ref.ownRelationshipKid}:${ref.counterpartyRelationshipKid}`
}

export function contactKeyAad(identityId: IdentityId, segmentId: SegmentId, counterpartyDid: string, ref: ContactKeyRef): Uint8Array {
  return canonicalBytes({ label: 'biset/vault/contact-key/aad/v2', identityId, segmentId, counterpartyDid, ownRelationshipKid: ref.ownRelationshipKid, counterpartyRelationshipKid: ref.counterpartyRelationshipKid })
}

export function assertContactKeyRecord(event: VaultEventV1, object: VaultObjectV1, plaintext: Uint8Array): ContactKeyV1 {
  if (event.kind !== 'contact-key.set' || event.objectRefs.length !== 1 || event.objectRefs[0] !== object.objectId) {
    throw new TypeError('contact key event does not reference its object')
  }
  const contactKey = decodeContactKey(plaintext)
  if (
    contactKey.identityId !== event.identityId || contactKey.createdAt !== event.createdAt ||
    event.targetIds.length !== 1 || event.targetIds[0] !== contactKeyTarget(contactKey.counterpartyDid, contactKey) ||
    !equalBytes(object.aad, contactKeyAad(contactKey.identityId, object.segmentId, contactKey.counterpartyDid, contactKey))
  ) throw new TypeError('contact key record metadata does not match')
  return contactKey
}

function assertContactKey(value: ContactKeyV1): void {
  if (
    !value.identityId || value.kind !== 'contact-key' || !value.counterpartyDid ||
    value.ownX25519PrivateKey.length !== 32 || value.ownEd25519PrivateKey.length !== 32 ||
    value.counterpartyPublicKey.length !== 32 || Number.isNaN(Date.parse(value.createdAt)) || !value.seedId
  ) throw new TypeError('contact key is invalid')
  if (value.supersedes !== undefined && contactKeyRef(value.supersedes) === contactKeyRef(value)) throw new TypeError('contact key cannot supersede itself')

  const ownDid = value.ownRelationshipKid.split('#', 1)[0]!
  if (!ownDid.startsWith('did:peer:2.')) throw new TypeError('contact key own kid is not did:peer:2')
  let ownDoc: ReturnType<typeof decodePeerDid2>
  try { ownDoc = decodePeerDid2(ownDid) } catch { throw new TypeError('contact key own kid is invalid') }
  const service = ownDoc.service[0]?.serviceEndpoint
  if (!service?.uri || service.routing_keys.length !== 1) throw new TypeError('contact key own kid has no relationship mediator service')
  const expectedOwnDid = encodePeerDid2(
    x25519.getPublicKey(value.ownX25519PrivateKey),
    ed25519.getPublicKey(value.ownEd25519PrivateKey),
    { uri: service.uri, accept: service.accept, routingKeys: service.routing_keys },
  )
  if (ownDid !== expectedOwnDid || value.ownRelationshipKid !== `${ownDid}#key-1`) throw new TypeError('contact key own kid does not match its private keys')
  if (!value.counterpartyRelationshipKid.startsWith('did:peer:2.')) throw new TypeError('contact key counterparty kid is not did:peer:2')
  let counterpartyPublicKey: Uint8Array
  try {
    const counterpartyDid = value.counterpartyRelationshipKid.split('#', 1)[0]!
    counterpartyPublicKey = publicKeyOf(decodePeerDid2(counterpartyDid), value.counterpartyRelationshipKid)
  } catch {
    throw new TypeError('contact key counterparty kid is invalid')
  }
  if (!equalBytes(counterpartyPublicKey, value.counterpartyPublicKey)) throw new TypeError('contact key counterparty kid does not match its public key')
}

function copyContactKey(value: ContactKeyV1): ContactKeyV1 {
  return {
    ...value,
    ownX25519PrivateKey: value.ownX25519PrivateKey.slice(),
    ownEd25519PrivateKey: value.ownEd25519PrivateKey.slice(),
    counterpartyPublicKey: value.counterpartyPublicKey.slice(),
  }
}

/** Descriptor consumed by vault/credential-store.ts's generic reader and sink. */
export const contactKeyCredentialKind: VaultCredentialKind<ContactKeyV1, VaultCredentialEventReader> = {
  eventKind: 'contact-key.set',
  label: 'contact key',
  segmentLabel: 'contact key',
  readEvents: (events, identityId) => events.readCredentialEvents(identityId),
  assert: assertContactKeyRecord,
  build: buildContactKeyRecord,
  createdAtOf: value => value.createdAt,
  copy: copyContactKey,
}
