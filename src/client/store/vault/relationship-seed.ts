// The identity-wide secret every relationship did:peer is derived from
// (protocol/didcomm/peer.ts's deriveRelationshipPeerIdentity), and the key
// that signs this identity's DID Rotation (client/didcomm/rotation-key.ts).
// Kept in the Vault, so it travels only to this identity's current devices
// over Vault Sync -- never through the Wallet. Only its rotation key's public
// half is published, in the DID document.
//
// Deriving instead of minting at random is what keeps devices from racing:
// every device computes the same did:peer for the same counterparty. Removing
// a device replaces the seed (the removing device's candidate, whose rotation
// key the same document edit publishes), so the removed device can neither
// sign rotations nor derive the did:peers conversations move to.
//
// Which seed is in use is decided from the DID document alone
// (relationship-seed-bootstrap.ts): the one whose rotation key it publishes.
import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../../../protocol/canonical.ts'
import type { IdentityId, SegmentId } from '../../../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../../../protocol/vault.ts'
import { sha256 } from '@noble/hashes/sha2.js'
import { createVaultEvent, type VaultEventAuthor } from './events.ts'
import { encryptVaultObject } from './objects.ts'
import { VaultCredentialReader, VaultCredentialSink, type VaultCredentialKind, type VaultCredentialReaderOptions, type VaultCredentialSinkOptions, type VaultCredentialStoreResult } from './credential-store.ts'
import type { VaultCredentialEventReader } from './store.ts'

export interface RelationshipSeedV1 {
  version: 1
  kind: 'credential.relationship-seed'
  identityId: IdentityId
  /** Public name of `seed` (a hash prefix), so records can name each other. */
  seedId: string
  /** 32 random bytes. */
  seed: Uint8Array
  createdAt: string
  /** The did:webvh log version at which this device stored it (a record of
   * when; the DID document, not this, says whether it is in use). */
  afterVersion: number
  /** Kept for records written before the DID document became the seed's
   * authority; nothing writes it any more. */
  supersedesSeedId?: string
}

function relationshipSeedId(seed: Uint8Array): string {
  return bytesToBase64url(sha256(seed)).slice(0, 22)
}

/** A seed record for `seed`: a candidate this device made (a 32-byte random
 * value) that the DID document now names by its rotation key. */
export function relationshipSeedRecord(identityId: IdentityId, seed: Uint8Array, afterVersion: number, now = new Date()): RelationshipSeedV1 {
  if (seed.length !== 32) throw new TypeError('relationship seed must be 32 bytes')
  return { version: 1, kind: 'credential.relationship-seed', identityId, seedId: relationshipSeedId(seed), seed: seed.slice(), createdAt: now.toISOString(), afterVersion }
}

function encode(value: RelationshipSeedV1): Uint8Array {
  assertSeed(value)
  return canonicalBytes({
    version: value.version, kind: value.kind, identityId: value.identityId, seedId: value.seedId,
    seed: bytesToBase64url(value.seed), createdAt: value.createdAt, afterVersion: value.afterVersion,
    ...(value.supersedesSeedId === undefined ? {} : { supersedesSeedId: value.supersedesSeedId }),
  })
}

function decode(bytes: Uint8Array): RelationshipSeedV1 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('relationship seed is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('relationship seed must be an object')
  const v = input as Record<string, unknown>
  if (v.version !== 1 || v.kind !== 'credential.relationship-seed' || typeof v.identityId !== 'string' || typeof v.seedId !== 'string'
    || typeof v.seed !== 'string' || typeof v.createdAt !== 'string' || typeof v.afterVersion !== 'number'
    || (v.supersedesSeedId !== undefined && typeof v.supersedesSeedId !== 'string')) {
    throw new TypeError('relationship seed shape is invalid')
  }
  const value: RelationshipSeedV1 = {
    version: 1, kind: 'credential.relationship-seed', identityId: v.identityId, seedId: v.seedId, seed: base64urlToBytes(v.seed), createdAt: v.createdAt,
    afterVersion: v.afterVersion,
    ...(v.supersedesSeedId === undefined ? {} : { supersedesSeedId: v.supersedesSeedId }),
  }
  if (!equalBytes(bytes, encode(value))) throw new TypeError('relationship seed is not canonical')
  return value
}

function aad(identityId: IdentityId, segmentId: SegmentId, seedId: string): Uint8Array {
  return canonicalBytes({ label: 'biset/vault/relationship-seed/aad/v1', identityId, segmentId, seedId })
}

function assertSeed(value: RelationshipSeedV1): void {
  if (!value.identityId || value.kind !== 'credential.relationship-seed' || value.seed.length !== 32
    || value.seedId !== relationshipSeedId(value.seed) || Number.isNaN(Date.parse(value.createdAt))
    || !Number.isSafeInteger(value.afterVersion) || value.afterVersion < 0
    || value.supersedesSeedId === value.seedId) throw new TypeError('relationship seed is invalid')
}

function copy(value: RelationshipSeedV1): RelationshipSeedV1 { return { ...value, seed: value.seed.slice() } }

export function assertRelationshipSeedRecord(event: VaultEventV1, object: VaultObjectV1, plaintext: Uint8Array): RelationshipSeedV1 {
  if (event.kind !== 'credential.relationship-seed.set' || event.objectRefs.length !== 1 || event.objectRefs[0] !== object.objectId) {
    throw new TypeError('relationship seed event does not reference its object')
  }
  const value = decode(plaintext)
  if (value.identityId !== event.identityId || value.createdAt !== event.createdAt || event.targetIds.length !== 1
    || event.targetIds[0] !== `relationship-seed:${value.seedId}` || !equalBytes(object.aad, aad(value.identityId, object.segmentId, value.seedId))) {
    throw new TypeError('relationship seed record metadata does not match')
  }
  return value
}

const relationshipSeedKind: VaultCredentialKind<RelationshipSeedV1, VaultCredentialEventReader> = {
  eventKind: 'credential.relationship-seed.set',
  label: 'relationship seed',
  segmentLabel: 'relationship seed',
  readEvents: (events, identityId) => events.readCredentialEvents(identityId),
  assert: assertRelationshipSeedRecord,
  async build(value, context, signer) {
    assertSeed(value)
    if (context.identityId !== value.identityId || context.actorDeviceId !== signer.deviceId || !context.segmentId || context.segmentKey.length !== 32) {
      throw new TypeError('relationship seed build context is invalid')
    }
    const object = await encryptVaultObject(context.segmentKey, { segmentId: context.segmentId, plaintext: encode(value), aad: aad(context.identityId, context.segmentId, value.seedId) })
    const event = await createVaultEvent({
      identityId: context.identityId, actorDeviceId: context.actorDeviceId, actorSeq: context.actorSeq,
      kind: 'credential.relationship-seed.set', targetIds: [`relationship-seed:${value.seedId}`],
      objectRefs: [object.objectId], parents: [...context.parents], createdAt: value.createdAt,
    }, signer)
    return { object, event }
  },
  createdAtOf: value => value.createdAt,
  copy,
}


/** Every seed in the Vault. Which one is in use is not theirs to say: it is
 * the one whose rotation key the DID document publishes
 * (relationship-seed-bootstrap.ts). */
export class RelationshipSeedReader {
  private readonly reader: VaultCredentialReader<RelationshipSeedV1, VaultCredentialEventReader>
  constructor(options: VaultCredentialReaderOptions<VaultCredentialEventReader>) {
    this.reader = new VaultCredentialReader(relationshipSeedKind, options)
  }
  async readAll(): Promise<RelationshipSeedV1[]> {
    return (await this.reader.readAll()).map(copy)
  }
}

export class RelationshipSeedSink {
  private readonly sink: VaultCredentialSink<RelationshipSeedV1>
  constructor(options: VaultCredentialSinkOptions) {
    this.sink = new VaultCredentialSink(relationshipSeedKind, options)
  }
  store(value: RelationshipSeedV1): Promise<VaultCredentialStoreResult> { return this.sink.store(value) }
}
