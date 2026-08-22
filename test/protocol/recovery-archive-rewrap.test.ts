import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { createSegmentKeyWrap, unwrapSegmentKey, type SegmentKeyWrapSigner } from '../../src/vault/crypto.ts'
import { createVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/vault/objects.ts'
import { rewrapRecoveryArchiveForCurrentEpoch } from '../../src/vault/recovery-archive-rewrap.ts'
import type { RecoveryArchiveSnapshotV1 } from '../../src/vault/recovery-archive.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner & SegmentKeyWrapSigner = {
  deviceId: 'device-restored',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) },
}

describe('recovery archive current-epoch rewrap', () => {
  test('reissues every archived SegmentKey only to the new current MLS epoch and clears the transient VEK', async () => {
    const snapshot = await fixture()
    const vek = createSegmentKey()
    const verifierVek = vek.slice()
    const imports = await rewrapRecoveryArchiveForCurrentEpoch(snapshot, {
      async currentVaultEpoch() { return { selfGroupId: 'new-self-group', epoch: '9' } },
      async deriveVaultEpochKey() { return vek },
    }, signer, '2026-08-22T02:00:00.000Z')

    expect(imports).toMatchObject({ version: 1, identityId, keyWraps: [{ selfGroupId: 'new-self-group', sourceEpoch: '9', recipientEpoch: '9' }] })
    expect(await unwrapSegmentKey(verifierVek, imports.keyWraps[0]!, signer)).toEqual(snapshot.segmentKeys[0]?.key)
    expect(vek).toEqual(new Uint8Array(32))
    expect(imports.objects[0]?.objectId).toBe(snapshot.objects[0]?.objectId)
  })

  test('refuses to make a new grant from an invalid archive snapshot', async () => {
    const snapshot = await fixture()
    await expect(rewrapRecoveryArchiveForCurrentEpoch({ ...snapshot, segmentKeys: [] }, {
      async currentVaultEpoch() { return { selfGroupId: 'new-self-group', epoch: '9' } }, async deriveVaultEpochKey() { return createSegmentKey() },
    }, signer, '2026-08-22T02:00:00.000Z')).rejects.toThrow('missing a SegmentKey')
  })
})

async function fixture(): Promise<RecoveryArchiveSnapshotV1> {
  const segmentKey = createSegmentKey()
  const object = await encryptVaultObject(segmentKey, { segmentId: 'segment-1', plaintext: new Uint8Array([1, 2]), aad: new Uint8Array([3]) })
  const event = await createVaultEvent({ identityId, actorDeviceId: signer.deviceId, actorSeq: 1, kind: 'message.add', targetIds: ['message-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-22T00:00:00.000Z' }, signer)
  return { version: 1, identityId, manifest: buildVaultManifest(identityId, [event.id], [object.objectId], '2026-08-22T00:00:00.000Z'), events: [event], objects: [object], segmentKeys: [{ segmentId: 'segment-1', key: segmentKey }], createdAt: '2026-08-22T00:00:00.000Z' }
}
