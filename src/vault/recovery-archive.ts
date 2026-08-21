import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../protocol/canonical.ts'
import type { IdentityId, SegmentId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import { verifyVaultManifest, type VaultManifestV1 } from './manifest.ts'
import { verifyVaultObjectIntegrity } from './objects.ts'

const RECOVERY_KEY_BYTES = 32
const NONCE_BYTES = 12

/** A user-held, independent secret. It is neither an MLS secret nor a device key. */
export function createRecoveryKey(): Uint8Array {
  const key = new Uint8Array(RECOVERY_KEY_BYTES)
  crypto.getRandomValues(key)
  return key
}

/**
 * The encrypted archive contains original ciphertext records plus every
 * SegmentKey required to reopen them. It intentionally contains neither an
 * MLS exporter secret nor a device signing key; a restored device creates new
 * current-epoch wraps after it joins/recreates its self group.
 */
export interface RecoveryArchiveSnapshotV1 {
  version: 1
  identityId: IdentityId
  manifest: VaultManifestV1
  events: VaultEventV1[]
  objects: VaultObjectV1[]
  segmentKeys: Array<{ segmentId: SegmentId; key: Uint8Array }>
  createdAt: string
}

/** Serializable outer envelope; only this ciphertext is suitable for export. */
export interface RecoveryArchiveV1 {
  version: 1
  kind: 'biset.recovery-archive'
  identityId: IdentityId
  createdAt: string
  nonce: Uint8Array
  ciphertext: Uint8Array
  ciphertextHash: Uint8Array
  plaintextLength: number
  aad: Uint8Array
}

export async function createRecoveryArchive(recoveryKey: Uint8Array, snapshot: RecoveryArchiveSnapshotV1): Promise<RecoveryArchiveV1> {
  assertRecoveryKey(recoveryKey)
  await assertSnapshot(snapshot)
  const nonce = randomNonce()
  const aad = recoveryArchiveAad(snapshot.identityId, snapshot.createdAt)
  const plaintext = encodeRecoveryArchiveSnapshot(snapshot)
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: arrayBuffer(nonce), additionalData: arrayBuffer(aad) },
    await importRecoveryKey(recoveryKey, ['encrypt']),
    arrayBuffer(plaintext),
  ))
  return {
    version: 1,
    kind: 'biset.recovery-archive',
    identityId: snapshot.identityId,
    createdAt: snapshot.createdAt,
    nonce,
    ciphertext,
    ciphertextHash: await digest(ciphertext),
    plaintextLength: plaintext.length,
    aad,
  }
}

/** Decrypts and structurally verifies an archive entirely at the endpoint. */
export async function openRecoveryArchive(recoveryKey: Uint8Array, archive: RecoveryArchiveV1): Promise<RecoveryArchiveSnapshotV1> {
  assertRecoveryKey(recoveryKey)
  assertArchiveEnvelope(archive)
  if (!equalBytes(archive.ciphertextHash, await digest(archive.ciphertext))) throw new TypeError('recovery archive ciphertext hash does not match')
  const expectedAad = recoveryArchiveAad(archive.identityId, archive.createdAt)
  if (!equalBytes(archive.aad, expectedAad)) throw new TypeError('recovery archive AAD does not match metadata')
  let plaintext: Uint8Array
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: arrayBuffer(archive.nonce), additionalData: arrayBuffer(archive.aad) },
      await importRecoveryKey(recoveryKey, ['decrypt']),
      arrayBuffer(archive.ciphertext),
    ))
  } catch {
    throw new TypeError('recovery archive cannot be decrypted')
  }
  if (plaintext.length !== archive.plaintextLength) throw new TypeError('recovery archive plaintext length does not match')
  const snapshot = decodeRecoveryArchiveSnapshot(plaintext)
  if (snapshot.identityId !== archive.identityId || snapshot.createdAt !== archive.createdAt) throw new TypeError('recovery archive plaintext metadata does not match envelope')
  await assertSnapshot(snapshot)
  return copySnapshot(snapshot)
}

export function recoveryArchiveAad(identityId: IdentityId, createdAt: string): Uint8Array {
  if (!identityId || Number.isNaN(Date.parse(createdAt))) throw new TypeError('recovery archive identity and creation time are required')
  return canonicalBytes({ label: 'biset/recovery-archive/aad/v1', identityId, createdAt })
}

export function encodeRecoveryArchiveSnapshot(snapshot: RecoveryArchiveSnapshotV1): Uint8Array {
  return canonicalBytes(snapshotWire(snapshot))
}

export function decodeRecoveryArchiveSnapshot(bytes: Uint8Array): RecoveryArchiveSnapshotV1 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { throw new TypeError('recovery archive snapshot is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('recovery archive snapshot must be an object')
  const value = input as Record<string, unknown>
  if (value.version !== 1 || typeof value.identityId !== 'string' || typeof value.createdAt !== 'string' || !Array.isArray(value.events) || !Array.isArray(value.objects) || !Array.isArray(value.segmentKeys) || value.manifest === null || typeof value.manifest !== 'object') throw new TypeError('recovery archive snapshot shape is invalid')
  const snapshot: RecoveryArchiveSnapshotV1 = {
    version: 1,
    identityId: value.identityId,
    manifest: manifestFromWire(value.manifest as Record<string, unknown>),
    events: value.events.map(eventFromWire),
    objects: value.objects.map(objectFromWire),
    segmentKeys: value.segmentKeys.map(segmentKeyFromWire),
    createdAt: value.createdAt,
  }
  if (!equalBytes(bytes, encodeRecoveryArchiveSnapshot(snapshot))) throw new TypeError('recovery archive snapshot is not canonical')
  return snapshot
}

async function assertSnapshot(snapshot: RecoveryArchiveSnapshotV1): Promise<void> {
  if (snapshot.version !== 1 || !snapshot.identityId || Number.isNaN(Date.parse(snapshot.createdAt)) || snapshot.manifest.identityId !== snapshot.identityId || !verifyVaultManifest(snapshot.manifest)) throw new TypeError('recovery archive snapshot is invalid')
  const eventIds = new Set<string>()
  for (const event of snapshot.events) {
    if (event.identityId !== snapshot.identityId || eventIds.has(event.id)) throw new TypeError('recovery archive event set is invalid')
    eventIds.add(event.id)
  }
  const objectIds = new Set<string>()
  const segments = new Set<string>()
  for (const object of snapshot.objects) {
    if (objectIds.has(object.objectId) || !(await verifyVaultObjectIntegrity(object))) throw new TypeError('recovery archive object set is invalid')
    objectIds.add(object.objectId)
    segments.add(object.segmentId)
  }
  if (!sameSet(eventIds, new Set(snapshot.manifest.eventIds)) || !sameSet(objectIds, new Set(snapshot.manifest.objectIds))) throw new TypeError('recovery archive records do not match manifest')
  const segmentKeys = new Set<string>()
  for (const segment of snapshot.segmentKeys) {
    if (!segment.segmentId || segment.key.length !== RECOVERY_KEY_BYTES || segmentKeys.has(segment.segmentId)) throw new TypeError('recovery archive segment key set is invalid')
    segmentKeys.add(segment.segmentId)
  }
  if (![...segments].every(segmentId => segmentKeys.has(segmentId))) throw new TypeError('recovery archive is missing a SegmentKey')
}

function snapshotWire(value: RecoveryArchiveSnapshotV1) {
  return {
    version: value.version,
    identityId: value.identityId,
    manifest: manifestWire(value.manifest),
    events: value.events.map(eventWire),
    objects: value.objects.map(objectWire),
    segmentKeys: value.segmentKeys.map(segment => ({ segmentId: segment.segmentId, key: bytesToBase64url(segment.key) })),
    createdAt: value.createdAt,
  }
}

function manifestWire(value: VaultManifestV1) { return { version: value.version, identityId: value.identityId, eventIds: value.eventIds, objectIds: value.objectIds, root: value.root, createdAt: value.createdAt } }
function eventWire(value: VaultEventV1) { return { ...value, signature: bytesToBase64url(value.signature) } }
function objectWire(value: VaultObjectV1) { return { ...value, nonce: bytesToBase64url(value.nonce), ciphertext: bytesToBase64url(value.ciphertext), ciphertextHash: bytesToBase64url(value.ciphertextHash), aad: bytesToBase64url(value.aad) } }

function manifestFromWire(value: Record<string, unknown>): VaultManifestV1 {
  if (value.version !== 1 || typeof value.identityId !== 'string' || !Array.isArray(value.eventIds) || !value.eventIds.every(id => typeof id === 'string') || !Array.isArray(value.objectIds) || !value.objectIds.every(id => typeof id === 'string') || typeof value.root !== 'string' || typeof value.createdAt !== 'string') throw new TypeError('recovery archive manifest shape is invalid')
  return { version: 1, identityId: value.identityId, eventIds: [...value.eventIds], objectIds: [...value.objectIds], root: value.root, createdAt: value.createdAt }
}

function eventFromWire(value: unknown): VaultEventV1 {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('recovery archive event shape is invalid')
  const event = value as Record<string, unknown>
  if (event.version !== 1 || typeof event.id !== 'string' || typeof event.identityId !== 'string' || typeof event.actorDeviceId !== 'string' || typeof event.actorSeq !== 'number' || typeof event.kind !== 'string' || !Array.isArray(event.targetIds) || !event.targetIds.every(id => typeof id === 'string') || !Array.isArray(event.objectRefs) || !event.objectRefs.every(id => typeof id === 'string') || !Array.isArray(event.parents) || !event.parents.every(id => typeof id === 'string') || typeof event.createdAt !== 'string' || typeof event.signature !== 'string') throw new TypeError('recovery archive event shape is invalid')
  return { version: 1, id: event.id, identityId: event.identityId, actorDeviceId: event.actorDeviceId, actorSeq: event.actorSeq, kind: event.kind as VaultEventV1['kind'], targetIds: [...event.targetIds], objectRefs: [...event.objectRefs], parents: [...event.parents], createdAt: event.createdAt, signature: base64urlToBytes(event.signature) }
}

function objectFromWire(value: unknown): VaultObjectV1 {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('recovery archive object shape is invalid')
  const object = value as Record<string, unknown>
  if (object.version !== 1 || typeof object.objectId !== 'string' || typeof object.segmentId !== 'string' || typeof object.nonce !== 'string' || typeof object.ciphertext !== 'string' || typeof object.ciphertextHash !== 'string' || typeof object.plaintextLength !== 'number' || typeof object.aad !== 'string') throw new TypeError('recovery archive object shape is invalid')
  return { version: 1, objectId: object.objectId, segmentId: object.segmentId, nonce: base64urlToBytes(object.nonce), ciphertext: base64urlToBytes(object.ciphertext), ciphertextHash: base64urlToBytes(object.ciphertextHash), plaintextLength: object.plaintextLength, aad: base64urlToBytes(object.aad) }
}

function segmentKeyFromWire(value: unknown): { segmentId: SegmentId; key: Uint8Array } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('recovery archive SegmentKey shape is invalid')
  const segment = value as Record<string, unknown>
  if (typeof segment.segmentId !== 'string' || typeof segment.key !== 'string') throw new TypeError('recovery archive SegmentKey shape is invalid')
  return { segmentId: segment.segmentId, key: base64urlToBytes(segment.key) }
}

function copySnapshot(value: RecoveryArchiveSnapshotV1): RecoveryArchiveSnapshotV1 {
  return { ...value, manifest: { ...value.manifest, eventIds: [...value.manifest.eventIds], objectIds: [...value.manifest.objectIds] }, events: value.events.map(event => ({ ...event, targetIds: [...event.targetIds], objectRefs: [...event.objectRefs], parents: [...event.parents], signature: event.signature.slice() })), objects: value.objects.map(object => ({ ...object, nonce: object.nonce.slice(), ciphertext: object.ciphertext.slice(), ciphertextHash: object.ciphertextHash.slice(), aad: object.aad.slice() })), segmentKeys: value.segmentKeys.map(segment => ({ segmentId: segment.segmentId, key: segment.key.slice() })) }
}

function assertArchiveEnvelope(value: RecoveryArchiveV1): void {
  if (value.version !== 1 || value.kind !== 'biset.recovery-archive' || !value.identityId || Number.isNaN(Date.parse(value.createdAt)) || value.nonce.length !== NONCE_BYTES || value.ciphertext.length === 0 || value.ciphertextHash.length !== 32 || !Number.isSafeInteger(value.plaintextLength) || value.plaintextLength < 0 || value.aad.length === 0) throw new TypeError('recovery archive envelope is invalid')
}

function sameSet(left: Set<string>, right: Set<string>): boolean { return left.size === right.size && [...left].every(value => right.has(value)) }
function randomNonce(): Uint8Array { const nonce = new Uint8Array(NONCE_BYTES); crypto.getRandomValues(nonce); return nonce }
async function digest(bytes: Uint8Array): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBuffer(bytes))) }
async function importRecoveryKey(key: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> { return crypto.subtle.importKey('raw', arrayBuffer(key), 'AES-GCM', false, usages) }
function assertRecoveryKey(key: Uint8Array): void { if (key.length !== RECOVERY_KEY_BYTES) throw new TypeError('recovery key must be 32 bytes') }
function arrayBuffer(bytes: Uint8Array): ArrayBuffer { const copy = new Uint8Array(bytes.length); copy.set(bytes); return copy.buffer }
