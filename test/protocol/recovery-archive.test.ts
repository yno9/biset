import { describe, expect, test } from 'bun:test'
import { buildVaultManifest } from '../../src/client/store/vault/manifest.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/client/store/vault/objects.ts'
import { createRecoveryArchive, createRecoveryKey, decodeRecoveryArchive, encodeRecoveryArchive, openRecoveryArchive, type RecoveryArchiveSnapshotV1 } from '../../src/client/store/vault/recovery-archive.ts'
import { createVaultEvent, type VaultEventSigner } from '../../src/client/store/vault/events.ts'
import { bytesToBase64url, equalBytes } from '../../src/shared/protocol/canonical.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('user-owned recovery archive', () => {
  test('encrypts an entire vault snapshot and restores its SegmentKeys only with the independent recovery key', async () => {
    const snapshot = await fixture()
    const recoveryKey = createRecoveryKey()
    const archive = await createRecoveryArchive(recoveryKey, snapshot)

    expect(archive.ciphertext).not.toEqual(snapshot.segmentKeys[0]!.key)
    const restored = await openRecoveryArchive(recoveryKey, archive)
    expect(restored.manifest.root).toBe(snapshot.manifest.root)
    expect(restored.events[0]?.id).toBe(snapshot.events[0]?.id)
    expect(restored.objects[0]?.objectId).toBe(snapshot.objects[0]?.objectId)
    expect(restored.segmentKeys[0]?.key).toEqual(snapshot.segmentKeys[0]?.key)
  })

  test('rejects a wrong recovery key or a changed exported ciphertext', async () => {
    const archive = await createRecoveryArchive(createRecoveryKey(), await fixture())
    await expect(openRecoveryArchive(createRecoveryKey(), archive)).rejects.toThrow('cannot be decrypted')
    const modified = { ...archive, ciphertext: archive.ciphertext.map((byte, index) => index === 0 ? byte ^ 1 : byte) }
    await expect(openRecoveryArchive(createRecoveryKey(), modified)).rejects.toThrow('hash')
  })

  test('does not export a snapshot when any encrypted object lacks its SegmentKey', async () => {
    const snapshot = await fixture()
    await expect(createRecoveryArchive(createRecoveryKey(), { ...snapshot, segmentKeys: [] })).rejects.toThrow('missing a SegmentKey')
  })

  test('uses a canonical encrypted-only file representation for browser export/import', async () => {
    const snapshot = await fixture()
    const recoveryKey = createRecoveryKey()
    const archive = await createRecoveryArchive(recoveryKey, snapshot)
    const bytes = encodeRecoveryArchive(archive)
    const text = new TextDecoder().decode(bytes)

    expect(text).not.toContain(bytesToBase64url(snapshot.segmentKeys[0]!.key))
    expect(decodeRecoveryArchive(bytes)).toEqual(archive)
    await expect(openRecoveryArchive(recoveryKey, decodeRecoveryArchive(bytes))).resolves.toMatchObject({ manifest: { root: snapshot.manifest.root } })
    await expect(() => decodeRecoveryArchive(new TextEncoder().encode(`${text} `))).toThrow('not canonical')
  })
})

async function fixture(): Promise<RecoveryArchiveSnapshotV1> {
  const segmentKey = createSegmentKey()
  const object = await encryptVaultObject(segmentKey, { segmentId: 'segment-1', plaintext: new TextEncoder().encode('contains encrypted OpenPGP credential and mail history'), aad: new TextEncoder().encode('archive-test') })
  const event = await createVaultEvent({ identityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add', targetIds: ['message-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-22T00:00:00.000Z' }, signer)
  return {
    version: 1,
    identityId,
    manifest: buildVaultManifest(identityId, [event.id], [object.objectId], '2026-08-22T00:00:00.000Z'),
    events: [event],
    objects: [object],
    segmentKeys: [{ segmentId: 'segment-1', key: segmentKey }],
    createdAt: '2026-08-22T00:00:00.000Z',
  }
}
