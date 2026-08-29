import { bytesToBase64url, canonicalHash } from '../protocol/canonical.ts'
import type { IdentityId, MlsEpoch, VaultEventId, VaultObjectId } from '../protocol/ids.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import type { VaultEventVerifier } from './events.ts'
import { verifyVaultEvent } from './events.ts'
import { diffVaultManifests, type VaultManifestV1, verifyVaultManifest } from './manifest.ts'
import { verifyVaultObjectIntegrity } from './objects.ts'

export interface RestoreTransferCursorV1 {
  version: 1
  identityId: IdentityId
  manifestRoot: string
  eventOffset: number
  objectOffset: number
}

/** One peer-to-peer frame. It is never accepted by the mediator. */
export interface RestoreTransferChunkV1 {
  version: 1
  identityId: IdentityId
  manifestRoot: string
  cursor: RestoreTransferCursorV1
  events: VaultEventV1[]
  objects: VaultObjectV1[]
  keyWraps: SegmentKeyWrapV1[]
  next?: RestoreTransferCursorV1
  chunkHash: string
}

export interface RestoreTransferSource {
  manifest(identityId: IdentityId): Promise<VaultManifestV1>
  readEvents(identityId: IdentityId, ids: readonly VaultEventId[]): Promise<VaultEventV1[]>
  readObjects(identityId: IdentityId, ids: readonly VaultObjectId[]): Promise<VaultObjectV1[]>
  /** Current-epoch grants for the segments included in this transfer frame. */
  readCurrentEpochWraps(identityId: IdentityId, segmentIds: readonly string[], recipientEpoch: MlsEpoch): Promise<SegmentKeyWrapV1[]>
}

export interface RestoreTransferVerifier {
  eventVerifier: VaultEventVerifier
  verifyCurrentEpochWrap(wrap: SegmentKeyWrapV1): Promise<boolean>
}

/**
 * Builds a bounded peer frame after manifest comparison. The caller supplies
 * an already-approved direct/relayed peer channel; this code has no core I/O.
 */
export async function createRestoreTransferChunk(
  source: RestoreTransferSource,
  requesterManifest: VaultManifestV1,
  cursor: RestoreTransferCursorV1 | undefined,
  recipientEpoch: MlsEpoch,
  maxRecords = 64,
): Promise<RestoreTransferChunkV1> {
  if (!Number.isSafeInteger(maxRecords) || maxRecords < 1) throw new TypeError('restore transfer maxRecords must be a positive safe integer')
  if (!verifyVaultManifest(requesterManifest)) throw new TypeError('requester manifest is invalid')
  const manifest = await source.manifest(requesterManifest.identityId)
  if (!verifyVaultManifest(manifest)) throw new TypeError('source manifest is invalid')
  const plan = diffVaultManifests(manifest, requesterManifest)
  const current = cursor ?? initialCursor(manifest)
  assertCursor(current, manifest, plan)

  const eventIds = plan.missingEvents.slice(current.eventOffset, current.eventOffset + maxRecords)
  const remaining = maxRecords - eventIds.length
  const objectIds = remaining === 0 ? [] : plan.missingObjects.slice(current.objectOffset, current.objectOffset + remaining)
  const events = await source.readEvents(manifest.identityId, eventIds)
  const objects = await source.readObjects(manifest.identityId, objectIds)
  assertExactIds(events.map(event => event.id), eventIds, 'events')
  assertExactIds(objects.map(object => object.objectId), objectIds, 'objects')
  const segmentIds = [...new Set(objects.map(object => object.segmentId))].sort()
  const keyWraps = await source.readCurrentEpochWraps(manifest.identityId, segmentIds, recipientEpoch)
  assertWrapCoverage(keyWraps, manifest.identityId, segmentIds, recipientEpoch)
  const nextEventOffset = current.eventOffset + eventIds.length
  const nextObjectOffset = current.objectOffset + objectIds.length
  const next = nextEventOffset === plan.missingEvents.length && nextObjectOffset === plan.missingObjects.length
    ? undefined
    : { version: 1 as const, identityId: manifest.identityId, manifestRoot: manifest.root, eventOffset: nextEventOffset, objectOffset: nextObjectOffset }
  const unsigned = { version: 1 as const, identityId: manifest.identityId, manifestRoot: manifest.root, cursor: copyCursor(current), events: events.map(copyEvent), objects: objects.map(copyObject), keyWraps: keyWraps.map(copyWrap), ...(next === undefined ? {} : { next: copyCursor(next) }) }
  return { ...unsigned, chunkHash: restoreTransferChunkHash(unsigned) }
}

/** Verifies one frame before a caller writes its records into the local vault. */
export async function verifyRestoreTransferChunk(
  chunk: RestoreTransferChunkV1,
  sourceManifest: VaultManifestV1,
  requesterManifest: VaultManifestV1,
  recipientEpoch: MlsEpoch,
  verifier: RestoreTransferVerifier,
): Promise<boolean> {
  if (!verifyVaultManifest(sourceManifest) || !verifyVaultManifest(requesterManifest)) return false
  if (chunk.version !== 1 || chunk.identityId !== sourceManifest.identityId || chunk.manifestRoot !== sourceManifest.root) return false
  const plan = diffVaultManifests(sourceManifest, requesterManifest)
  try { assertCursor(chunk.cursor, sourceManifest, plan) } catch { return false }
  const expectedEvents = plan.missingEvents.slice(chunk.cursor.eventOffset, chunk.cursor.eventOffset + chunk.events.length)
  const expectedObjects = plan.missingObjects.slice(chunk.cursor.objectOffset, chunk.cursor.objectOffset + chunk.objects.length)
  if (!sameIds(chunk.events.map(event => event.id), expectedEvents) || !sameIds(chunk.objects.map(object => object.objectId), expectedObjects)) return false
  const nextEventOffset = chunk.cursor.eventOffset + chunk.events.length
  const nextObjectOffset = chunk.cursor.objectOffset + chunk.objects.length
  const complete = nextEventOffset === plan.missingEvents.length && nextObjectOffset === plan.missingObjects.length
  if (complete !== (chunk.next === undefined)) return false
  if (!complete && nextEventOffset === chunk.cursor.eventOffset && nextObjectOffset === chunk.cursor.objectOffset) return false
  if (chunk.next && (chunk.next.eventOffset !== nextEventOffset || chunk.next.objectOffset !== nextObjectOffset)) return false
  if (chunk.next) {
    try { assertCursor(chunk.next, sourceManifest, plan) } catch { return false }
  }
  const unsigned = { version: chunk.version, identityId: chunk.identityId, manifestRoot: chunk.manifestRoot, cursor: chunk.cursor, events: chunk.events, objects: chunk.objects, keyWraps: chunk.keyWraps, ...(chunk.next === undefined ? {} : { next: chunk.next }) }
  if (chunk.chunkHash !== restoreTransferChunkHash(unsigned)) return false
  if (!(await Promise.all(chunk.events.map(event => verifyVaultEvent(event, verifier.eventVerifier)))).every(Boolean)) return false
  if (!(await Promise.all(chunk.objects.map(verifyVaultObjectIntegrity))).every(Boolean)) return false
  const segmentIds = [...new Set(chunk.objects.map(object => object.segmentId))]
  try { assertWrapCoverage(chunk.keyWraps, chunk.identityId, segmentIds, recipientEpoch) } catch { return false }
  return (await Promise.all(chunk.keyWraps.map(wrap => verifier.verifyCurrentEpochWrap(wrap)))).every(Boolean)
}

export function restoreTransferChunkHash(chunk: Omit<RestoreTransferChunkV1, 'chunkHash'>): string {
  return canonicalHash('biset/restore-transfer-chunk/v1', {
    version: chunk.version,
    identityId: chunk.identityId,
    manifestRoot: chunk.manifestRoot,
    cursor: cursorWire(chunk.cursor),
    events: chunk.events.map(eventWire),
    objects: chunk.objects.map(objectWire),
    keyWraps: chunk.keyWraps.map(wrapWire),
    ...(chunk.next === undefined ? {} : { next: cursorWire(chunk.next) }),
  })
}

function initialCursor(manifest: VaultManifestV1): RestoreTransferCursorV1 {
  return { version: 1, identityId: manifest.identityId, manifestRoot: manifest.root, eventOffset: 0, objectOffset: 0 }
}

function assertCursor(cursor: RestoreTransferCursorV1, manifest: VaultManifestV1, plan: ReturnType<typeof diffVaultManifests>): void {
  if (cursor.version !== 1 || cursor.identityId !== manifest.identityId || cursor.manifestRoot !== manifest.root || !Number.isSafeInteger(cursor.eventOffset) || !Number.isSafeInteger(cursor.objectOffset) || cursor.eventOffset < 0 || cursor.objectOffset < 0 || cursor.eventOffset > plan.missingEvents.length || cursor.objectOffset > plan.missingObjects.length) throw new TypeError('restore transfer cursor is invalid')
}

function assertExactIds(actual: readonly string[], expected: readonly string[], name: string): void {
  if (!sameIds(actual, expected)) throw new TypeError(`restore source returned unexpected ${name}`)
}

function sameIds(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((id, index) => id === expected[index])
}

function assertWrapCoverage(wraps: readonly SegmentKeyWrapV1[], identityId: IdentityId, segmentIds: readonly string[], recipientEpoch: MlsEpoch): void {
  const required = new Set(segmentIds)
  const covered = new Set<string>()
  for (const wrap of wraps) {
    if (wrap.identityId !== identityId || wrap.recipientEpoch !== recipientEpoch || !required.has(wrap.segmentId) || covered.has(wrap.segmentId)) throw new TypeError('restore transfer has an unexpected current-epoch SegmentKeyWrap')
    covered.add(wrap.segmentId)
  }
  if (segmentIds.some(segmentId => !covered.has(segmentId))) throw new TypeError('restore transfer is missing a current-epoch SegmentKeyWrap')
}

function copyCursor(value: RestoreTransferCursorV1): RestoreTransferCursorV1 { return { ...value } }
function cursorWire(value: RestoreTransferCursorV1) { return { version: value.version, identityId: value.identityId, manifestRoot: value.manifestRoot, eventOffset: value.eventOffset, objectOffset: value.objectOffset } }
function copyEvent(value: VaultEventV1): VaultEventV1 { return { ...value, ...(value.actorCredential ? { actorCredential: value.actorCredential.slice() } : {}), targetIds: [...value.targetIds], objectRefs: [...value.objectRefs], parents: [...value.parents], signature: value.signature.slice() } }
function copyObject(value: VaultObjectV1): VaultObjectV1 { return { ...value, nonce: value.nonce.slice(), ciphertext: value.ciphertext.slice(), ciphertextHash: value.ciphertextHash.slice(), aad: value.aad.slice() } }
function copyWrap(value: SegmentKeyWrapV1): SegmentKeyWrapV1 { return { ...value, nonce: value.nonce.slice(), aad: value.aad.slice(), wrappedSegmentKey: value.wrappedSegmentKey.slice(), signature: value.signature.slice() } }
function eventWire(value: VaultEventV1) { return { version: value.version, id: value.id, identityId: value.identityId, actorDeviceId: value.actorDeviceId, ...(value.actorCredential ? { actorCredential: bytesToBase64url(value.actorCredential) } : {}), actorSeq: value.actorSeq, kind: value.kind, targetIds: value.targetIds, objectRefs: value.objectRefs, parents: value.parents, createdAt: value.createdAt, signature: bytesToBase64url(value.signature) } }
function objectWire(value: VaultObjectV1) { return { ...value, nonce: bytesToBase64url(value.nonce), ciphertext: bytesToBase64url(value.ciphertext), ciphertextHash: bytesToBase64url(value.ciphertextHash), aad: bytesToBase64url(value.aad) } }
function wrapWire(value: SegmentKeyWrapV1) { return { ...value, nonce: bytesToBase64url(value.nonce), aad: bytesToBase64url(value.aad), wrappedSegmentKey: bytesToBase64url(value.wrappedSegmentKey), signature: bytesToBase64url(value.signature) } }
