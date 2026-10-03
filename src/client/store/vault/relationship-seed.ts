// The identity-wide secret every relationship did:peer is derived from
// (protocol/didcomm/peer.ts's deriveRelationshipPeerIdentity). Kept in the
// Vault, so it travels only to this identity's current devices over Vault
// Sync -- never through the Wallet, never in a DID document.
//
// Deriving instead of minting at random is what keeps devices from racing:
// a counterparty's INIT is delivered to every device at once, and each one
// computes the SAME relationship did:peer to answer with. Removing a device
// replaces the seed (the removing device mints a new one and the removed
// device never receives it), so the removed device can neither derive new
// relationships nor the ones existing relationships rotate to.
//
// Who mints, and when a seed is out of date, is decided from the did:webvh
// log alone (relationship-seed-bootstrap.ts): a seed is valid from the log
// version it was minted at (`afterVersion`), and stops being so once a later
// entry removes a device key.
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
  /** The did:webvh log version this seed was minted at. A later entry that
   * removes a device key makes the seed stale (the removed device has it). */
  afterVersion: number
  /** The seed this one replaced (a device removal). */
  supersedesSeedId?: string
}

function relationshipSeedId(seed: Uint8Array): string {
  return bytesToBase64url(sha256(seed)).slice(0, 22)
}

/** A brand-new seed for `identityId`. */
export function mintRelationshipSeed(identityId: IdentityId, afterVersion: number, supersedes?: RelationshipSeedV1, now = new Date()): RelationshipSeedV1 {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  return {
    version: 1, kind: 'credential.relationship-seed', identityId, seedId: relationshipSeedId(seed), seed,
    createdAt: now.toISOString(), afterVersion, ...(supersedes ? { supersedesSeedId: supersedes.seedId } : {}),
  }
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

/** The current seed: of those nothing supersedes, the one minted at the
 * latest log version. Should two ever tie (only one device is designated to
 * mint, but its retries could race), every device breaks it the same way
 * (latest `createdAt`, then smallest `seedId`) so all derive from the same. */
export function selectCurrentRelationshipSeed(values: readonly RelationshipSeedV1[]): RelationshipSeedV1 | undefined {
  const superseded = new Set(values.flatMap(value => value.supersedesSeedId ? [value.supersedesSeedId] : []))
  return values
    .filter(value => !superseded.has(value.seedId))
    .sort((a, b) => b.afterVersion - a.afterVersion || Date.parse(b.createdAt) - Date.parse(a.createdAt) || (a.seedId < b.seedId ? -1 : a.seedId > b.seedId ? 1 : 0))[0]
}

export class RelationshipSeedReader {
  private readonly reader: VaultCredentialReader<RelationshipSeedV1, VaultCredentialEventReader>
  constructor(options: VaultCredentialReaderOptions<VaultCredentialEventReader>) {
    this.reader = new VaultCredentialReader(relationshipSeedKind, options)
  }
  async current(): Promise<RelationshipSeedV1 | undefined> {
    const value = selectCurrentRelationshipSeed(await this.reader.readAll())
    return value ? copy(value) : undefined
  }
}

export class RelationshipSeedSink {
  private readonly sink: VaultCredentialSink<RelationshipSeedV1>
  constructor(options: VaultCredentialSinkOptions) {
    this.sink = new VaultCredentialSink(relationshipSeedKind, options)
  }
  store(value: RelationshipSeedV1): Promise<VaultCredentialStoreResult> { return this.sink.store(value) }
}
