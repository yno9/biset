import type { SegmentKeyWrapSigner } from './crypto.ts'
import { openRecoveryArchive, type RecoveryArchiveV1 } from './recovery-archive.ts'
import { rewrapRecoveryArchiveForCurrentEpoch, type RecoveryArchiveImportRecordsV1 } from './recovery-archive-rewrap.ts'
import type { VaultEpochKeyResolver } from './segment-key-resolver.ts'
import type { RecoveryArchiveImportStore } from './store.ts'

/**
 * Endpoint-only archive restore transaction. A successful result means raw
 * records and current wraps are durable; callers must still rebuild JMAP
 * projection before presenting the account as restored.
 */
export async function importRecoveryArchive(
  archive: RecoveryArchiveV1,
  recoveryKey: Uint8Array,
  epochs: VaultEpochKeyResolver,
  signer: SegmentKeyWrapSigner,
  store: RecoveryArchiveImportStore,
  grantedAt: string,
): Promise<RecoveryArchiveImportRecordsV1> {
  const snapshot = await openRecoveryArchive(recoveryKey, archive)
  try {
    const records = await rewrapRecoveryArchiveForCurrentEpoch(snapshot, epochs, signer, grantedAt)
    await store.commitRecoveryArchive({
      identityId: records.identityId,
      events: records.events.map(event => ({ ...event, identityId: records.identityId })),
      objects: records.objects.map(object => ({ ...object, identityId: records.identityId })),
      keyWraps: records.keyWraps,
    })
    return records
  } finally {
    for (const segment of snapshot.segmentKeys) segment.key.fill(0)
  }
}
