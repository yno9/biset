import type { IdentityId, MlsEpoch } from '../shared/protocol/ids.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../shared/protocol/vault.ts'
import type { VaultManifestV1 } from './manifest.ts'
import type { RestoreTransferChunkV1, RestoreTransferCursorV1, RestoreTransferVerifier } from './restore-transfer.ts'
import { verifyRestoreTransferChunk } from './restore-transfer.ts'

export interface RestoreTransferSessionV1 {
  version: 1
  identityId: IdentityId
  requesterDeviceId: string
  sourceManifest: VaultManifestV1
  requesterManifest: VaultManifestV1
  /** Missing only once the final verified frame has committed. */
  next?: RestoreTransferCursorV1
  completed: boolean
  lastChunkHash: string
  updatedAt: string
}

export interface RestoreTransferChunkCommit {
  session: RestoreTransferSessionV1
  chunk: RestoreTransferChunkV1
  objects: VaultObjectV1[]
  events: VaultEventV1[]
  keyWraps: SegmentKeyWrapV1[]
}

/** The endpoint persistence layer must make records and session cursor atomic. */
export interface RestoreTransferReceiverStore {
  readRestoreTransferSession(identityId: IdentityId, requesterDeviceId: string): Promise<RestoreTransferSessionV1 | undefined>
  commitRestoreTransferChunk(input: RestoreTransferChunkCommit): Promise<void>
}

export type RestoreTransferReceiveResult =
  | { kind: 'committed'; session: RestoreTransferSessionV1 }
  | { kind: 'duplicate'; session: RestoreTransferSessionV1 }

/**
 * Enforces ordered, resumable import. The store receives only verified
 * ciphertext/event/wrap records and never contacts the mediator.
 */
export async function receiveRestoreTransferChunk(
  store: RestoreTransferReceiverStore,
  requesterDeviceId: string,
  chunk: RestoreTransferChunkV1,
  sourceManifest: VaultManifestV1,
  requesterManifest: VaultManifestV1,
  recipientEpoch: MlsEpoch,
  verifier: RestoreTransferVerifier,
  now: () => Date = () => new Date(),
): Promise<RestoreTransferReceiveResult> {
  if (!requesterDeviceId) throw new TypeError('restore transfer requester device is required')
  if (!(await verifyRestoreTransferChunk(chunk, sourceManifest, requesterManifest, recipientEpoch, verifier))) throw new TypeError('restore transfer chunk verification failed')
  const existing = await store.readRestoreTransferSession(chunk.identityId, requesterDeviceId)
  if (existing) {
    assertSession(existing, sourceManifest, requesterManifest, requesterDeviceId)
    if (existing.completed) {
      if (existing.lastChunkHash === chunk.chunkHash) return { kind: 'duplicate', session: copySession(existing) }
      throw new TypeError('restore transfer session is already complete')
    }
    if (!sameCursor(existing.next, chunk.cursor)) throw new TypeError('restore transfer cursor is out of order')
  } else if (chunk.cursor.eventOffset !== 0 || chunk.cursor.objectOffset !== 0) {
    throw new TypeError('restore transfer must begin at the initial cursor')
  }
  const session: RestoreTransferSessionV1 = {
    version: 1,
    identityId: chunk.identityId,
    requesterDeviceId,
    sourceManifest: copyManifest(sourceManifest),
    requesterManifest: copyManifest(requesterManifest),
    ...(chunk.next === undefined ? {} : { next: copyCursor(chunk.next) }),
    completed: chunk.next === undefined,
    lastChunkHash: chunk.chunkHash,
    updatedAt: now().toISOString(),
  }
  await store.commitRestoreTransferChunk({ session, chunk: copyChunk(chunk), objects: chunk.objects.map(copyObject), events: chunk.events.map(copyEvent), keyWraps: chunk.keyWraps.map(copyWrap) })
  return { kind: 'committed', session: copySession(session) }
}

function assertSession(value: RestoreTransferSessionV1, source: VaultManifestV1, requester: VaultManifestV1, requesterDeviceId: string): void {
  if (value.version !== 1 || value.identityId !== source.identityId || value.requesterDeviceId !== requesterDeviceId || value.sourceManifest.root !== source.root || value.requesterManifest.root !== requester.root) throw new TypeError('restore transfer session does not match this restore')
}

function sameCursor(left: RestoreTransferCursorV1 | undefined, right: RestoreTransferCursorV1 | undefined): boolean {
  return left?.version === right?.version && left?.identityId === right?.identityId && left?.manifestRoot === right?.manifestRoot && left?.eventOffset === right?.eventOffset && left?.objectOffset === right?.objectOffset
}

function copyManifest(value: VaultManifestV1): VaultManifestV1 { return { ...value, eventIds: [...value.eventIds], objectIds: [...value.objectIds] } }
function copyCursor(value: RestoreTransferCursorV1): RestoreTransferCursorV1 { return { ...value } }
function copySession(value: RestoreTransferSessionV1): RestoreTransferSessionV1 { return { ...value, sourceManifest: copyManifest(value.sourceManifest), requesterManifest: copyManifest(value.requesterManifest), ...(value.next === undefined ? {} : { next: copyCursor(value.next) }) } }
function copyChunk(value: RestoreTransferChunkV1): RestoreTransferChunkV1 { return { ...value, cursor: copyCursor(value.cursor), events: value.events.map(copyEvent), objects: value.objects.map(copyObject), keyWraps: value.keyWraps.map(copyWrap), ...(value.next === undefined ? {} : { next: copyCursor(value.next) }) } }
function copyEvent(value: VaultEventV1): VaultEventV1 { return { ...value, ...(value.actorCredential ? { actorCredential: value.actorCredential.slice() } : {}), targetIds: [...value.targetIds], objectRefs: [...value.objectRefs], parents: [...value.parents], signature: value.signature.slice() } }
function copyObject(value: VaultObjectV1): VaultObjectV1 { return { ...value, nonce: value.nonce.slice(), ciphertext: value.ciphertext.slice(), ciphertextHash: value.ciphertextHash.slice(), aad: value.aad.slice() } }
function copyWrap(value: SegmentKeyWrapV1): SegmentKeyWrapV1 { return { ...value, nonce: value.nonce.slice(), aad: value.aad.slice(), wrappedSegmentKey: value.wrappedSegmentKey.slice(), signature: value.signature.slice() } }
