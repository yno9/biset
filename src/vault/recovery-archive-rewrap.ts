import type { IdentityId } from '../shared/protocol/ids.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../shared/protocol/vault.ts'
import { createSegmentKeyWrap, type SegmentKeyWrapSigner } from './crypto.ts'
import { assertRecoveryArchiveSnapshot, type RecoveryArchiveSnapshotV1 } from './recovery-archive.ts'
import type { VaultEpochKeyResolver } from './segment-key-resolver.ts'

export interface RecoveryArchiveImportRecordsV1 {
  version: 1
  identityId: IdentityId
  events: VaultEventV1[]
  objects: VaultObjectV1[]
  /** Fresh current-self-group grants, never archived historical wraps. */
  keyWraps: SegmentKeyWrapV1[]
}

/**
 * Converts a decrypted archive into records for a newly authorised endpoint.
 * The archive's SegmentKeys are rewrapped only for the current MLS epoch; old
 * wraps, VEKs, and device keys are neither imported nor retained.
 */
export async function rewrapRecoveryArchiveForCurrentEpoch(
  snapshot: RecoveryArchiveSnapshotV1,
  epochs: VaultEpochKeyResolver,
  signer: SegmentKeyWrapSigner,
  grantedAt: string,
): Promise<RecoveryArchiveImportRecordsV1> {
  await assertRecoveryArchiveSnapshot(snapshot)
  if (Number.isNaN(Date.parse(grantedAt))) throw new TypeError('recovery archive grant time is invalid')
  const current = await epochs.currentVaultEpoch(snapshot.identityId)
  if (!current.selfGroupId || !current.epoch) throw new TypeError('recovery archive import has no current MLS self group')
  const vek = await epochs.deriveVaultEpochKey(snapshot.identityId, current.selfGroupId, current.epoch)
  try {
    if (vek.length !== 32) throw new TypeError('recovery archive current VEK is invalid')
    const keyWraps = await Promise.all(snapshot.segmentKeys.map(segment => createSegmentKeyWrap(vek, segment.key, {
      identityId: snapshot.identityId,
      selfGroupId: current.selfGroupId,
      segmentId: segment.segmentId,
      sourceEpoch: current.epoch,
      recipientEpoch: current.epoch,
      grantorDeviceId: signer.deviceId,
      grantedAt,
    }, signer)))
    return {
      version: 1,
      identityId: snapshot.identityId,
      events: snapshot.events.map(copyEvent),
      objects: snapshot.objects.map(copyObject),
      keyWraps: keyWraps.map(copyWrap),
    }
  } finally {
    vek.fill(0)
  }
}

function copyEvent(value: VaultEventV1): VaultEventV1 { return { ...value, ...(value.actorCredential ? { actorCredential: value.actorCredential.slice() } : {}), targetIds: [...value.targetIds], objectRefs: [...value.objectRefs], parents: [...value.parents], signature: value.signature.slice() } }
function copyObject(value: VaultObjectV1): VaultObjectV1 { return { ...value, nonce: value.nonce.slice(), ciphertext: value.ciphertext.slice(), ciphertextHash: value.ciphertextHash.slice(), aad: value.aad.slice() } }
function copyWrap(value: SegmentKeyWrapV1): SegmentKeyWrapV1 { return { ...value, nonce: value.nonce.slice(), aad: value.aad.slice(), wrappedSegmentKey: value.wrappedSegmentKey.slice(), signature: value.signature.slice() } }
