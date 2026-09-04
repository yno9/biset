import { describe, expect, test } from 'bun:test'
import { createRecoveryArchive, createRecoveryKey, type RecoveryArchiveSnapshotV1 } from '../../src/vault/recovery-archive.ts'
import { RECOVERY_ARCHIVE_MEDIA_TYPE, readRecoveryArchiveFile, recoveryArchiveBlob, recoveryArchiveFileName } from '../../src/vault/recovery-archive-file.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/vault/objects.ts'
import { createVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { equalBytes } from '../../src/shared/protocol/canonical.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('recovery archive browser file boundary', () => {
  test('creates and reads an encrypted-only Blob without putting the identity in its filename', async () => {
    const archive = await createRecoveryArchive(createRecoveryKey(), await fixture())
    const blob = recoveryArchiveBlob(archive)
    expect(blob.type).toBe(RECOVERY_ARCHIVE_MEDIA_TYPE)
    expect(recoveryArchiveFileName(archive)).toBe('biset-recovery-2026-08-22.biset-recovery.json')
    expect(recoveryArchiveFileName(archive)).not.toContain('alice')
    expect(await readRecoveryArchiveFile(blob)).toEqual(archive)
  })

  test('rejects an empty selected file before decoding', async () => {
    await expect(readRecoveryArchiveFile(new Blob())).rejects.toThrow('empty')
  })
})

async function fixture(): Promise<RecoveryArchiveSnapshotV1> {
  const segmentKey = createSegmentKey()
  const object = await encryptVaultObject(segmentKey, { segmentId: 'segment-1', plaintext: new Uint8Array([1]), aad: new Uint8Array([2]) })
  const event = await createVaultEvent({ identityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add', targetIds: ['message-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-22T00:00:00.000Z' }, signer)
  return { version: 1, identityId, manifest: buildVaultManifest(identityId, [event.id], [object.objectId], '2026-08-22T00:00:00.000Z'), events: [event], objects: [object], segmentKeys: [{ segmentId: 'segment-1', key: segmentKey }], createdAt: '2026-08-22T00:00:00.000Z' }
}
