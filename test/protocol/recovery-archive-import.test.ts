import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/shared/protocol/canonical.ts'
import { createRecoveryArchive, createRecoveryKey, type RecoveryArchiveSnapshotV1 } from '../../src/vault/recovery-archive.ts'
import { importRecoveryArchive } from '../../src/vault/recovery-archive-import.ts'
import { createVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/vault/objects.ts'
import type { SegmentKeyWrapSigner } from '../../src/vault/crypto.ts'
import type { RecoveryArchiveImportCommit } from '../../src/vault/store.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner & SegmentKeyWrapSigner = {
  deviceId: 'device-restored',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) },
}

describe('recovery archive import', () => {
  test('atomically hands decrypted archive records to local storage with newly issued current-epoch wraps', async () => {
    const snapshot = await fixture()
    const recoveryKey = createRecoveryKey()
    const archive = await createRecoveryArchive(recoveryKey, snapshot)
    const commits: RecoveryArchiveImportCommit[] = []
    const vek = createSegmentKey()
    const records = await importRecoveryArchive(archive, recoveryKey, {
      async currentVaultEpoch() { return { selfGroupId: 'new-self-group', epoch: '4' } },
      async deriveVaultEpochKey() { return vek },
    }, signer, { async commitRecoveryArchive(input) { commits.push(input) } }, '2026-08-22T03:00:00.000Z')

    expect(commits).toHaveLength(1)
    expect(commits[0]).toMatchObject({ identityId, keyWraps: [{ selfGroupId: 'new-self-group', recipientEpoch: '4' }] })
    expect(records.objects[0]?.objectId).toBe(snapshot.objects[0]?.objectId)
    expect(vek).toEqual(new Uint8Array(32))
  })

  test('does not write any local record when the recovery key is wrong', async () => {
    const snapshot = await fixture()
    const archive = await createRecoveryArchive(createRecoveryKey(), snapshot)
    let committed = false
    await expect(importRecoveryArchive(archive, createRecoveryKey(), {
      async currentVaultEpoch() { return { selfGroupId: 'new-self-group', epoch: '4' } }, async deriveVaultEpochKey() { return createSegmentKey() },
    }, signer, { async commitRecoveryArchive() { committed = true } }, '2026-08-22T03:00:00.000Z')).rejects.toThrow('cannot be decrypted')
    expect(committed).toBe(false)
  })
})

async function fixture(): Promise<RecoveryArchiveSnapshotV1> {
  const segmentKey = createSegmentKey()
  const object = await encryptVaultObject(segmentKey, { segmentId: 'segment-1', plaintext: new Uint8Array([1]), aad: new Uint8Array([2]) })
  const event = await createVaultEvent({ identityId, actorDeviceId: signer.deviceId, actorSeq: 1, kind: 'message.add', targetIds: ['message-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-22T00:00:00.000Z' }, signer)
  return { version: 1, identityId, manifest: buildVaultManifest(identityId, [event.id], [object.objectId], '2026-08-22T00:00:00.000Z'), events: [event], objects: [object], segmentKeys: [{ segmentId: 'segment-1', key: segmentKey }], createdAt: '2026-08-22T00:00:00.000Z' }
}
