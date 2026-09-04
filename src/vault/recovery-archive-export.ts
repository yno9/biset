import type { IdentityId, SegmentId } from '../shared/protocol/ids.ts'
import { buildVaultManifest } from './manifest.ts'
import type { RecoveryArchiveSnapshotV1 } from './recovery-archive.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultRecordReader } from './store.ts'

/**
 * Builds the complete endpoint snapshot consumed by a user-owned archive.
 * It is deliberately local: caller-provided SegmentKeys are never sent to the
 * mediator or any transport adapter.
 */
export async function createRecoveryArchiveSnapshot(
  records: VaultRecordReader,
  segmentKeys: SegmentKeyResolver,
  identityId: IdentityId,
  createdAt: string,
): Promise<RecoveryArchiveSnapshotV1> {
  if (!identityId || Number.isNaN(Date.parse(createdAt))) throw new TypeError('recovery archive export identity and creation time are required')
  const [events, objects] = await Promise.all([records.readVaultEvents(identityId), records.readVaultObjects(identityId)])
  const segments = [...new Set(objects.map(object => object.segmentId))].sort()
  const keys: Array<{ segmentId: SegmentId; key: Uint8Array }> = []
  try {
    for (const segmentId of segments) keys.push({ segmentId, key: await segmentKeys.resolveSegmentKey(identityId, segmentId) })
    return {
      version: 1,
      identityId,
      manifest: buildVaultManifest(identityId, events.map(event => event.id), objects.map(object => object.objectId), createdAt),
      events,
      objects,
      segmentKeys: keys.map(value => ({ segmentId: value.segmentId, key: value.key.slice() })),
      createdAt,
    }
  } finally {
    for (const value of keys) value.key.fill(0)
  }
}
