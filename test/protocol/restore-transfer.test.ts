import { describe, expect, test } from 'bun:test'
import { createVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/vault/objects.ts'
import { createRestoreTransferChunk, restoreTransferChunkHash, verifyRestoreTransferChunk, type RestoreTransferSource } from '../../src/vault/restore-transfer.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign() { return new Uint8Array([7]) },
  async verify(_deviceId, _bytes, signature) { return signature[0] === 7 },
}

describe('peer restore transfer', () => {
  test('uses a manifest-first resumable transfer with verified frames and current wraps', async () => {
    const object = await encryptVaultObject(createSegmentKey(), { segmentId: 'segment-1', plaintext: new Uint8Array([1, 2]), aad: new Uint8Array([3]) })
    const event = await createVaultEvent({ identityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add', targetIds: ['message-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-21T00:00:00.000Z' }, signer)
    const sourceManifest = buildVaultManifest(identityId, [event.id], [object.objectId], '2026-08-21T00:00:00.000Z')
    const requesterManifest = buildVaultManifest(identityId, [], [], '2026-08-21T00:00:00.000Z')
    const wrap = { version: 1 as const, identityId, selfGroupId: 'self-1', segmentId: 'segment-1', sourceEpoch: '2', recipientEpoch: '3', nonce: new Uint8Array([1]), aad: new Uint8Array([2]), wrappedSegmentKey: new Uint8Array([3]), grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([4]) }
    const source: RestoreTransferSource = {
      async manifest() { return sourceManifest },
      async readEvents(_identity, ids) { return ids.map(id => id === event.id ? event : undefined).filter((value): value is typeof event => value !== undefined) },
      async readObjects(_identity, ids) { return ids.map(id => id === object.objectId ? object : undefined).filter((value): value is typeof object => value !== undefined) },
      async readCurrentEpochWraps(_identity, segmentIds, epoch) { return segmentIds.includes('segment-1') && epoch === '3' ? [wrap] : [] },
    }
    const verifier = { eventVerifier: signer, async verifyCurrentEpochWrap(value: typeof wrap) { return value.signature[0] === 4 } }

    const first = await createRestoreTransferChunk(source, requesterManifest, undefined, '3', 1)
    expect(first).toMatchObject({ events: [event], objects: [], keyWraps: [], next: { eventOffset: 1, objectOffset: 0 } })
    expect(await verifyRestoreTransferChunk(first, sourceManifest, requesterManifest, '3', verifier)).toBe(true)
    const stalledUnsigned = { ...first, events: [], next: { ...first.cursor } }
    expect(await verifyRestoreTransferChunk({ ...stalledUnsigned, chunkHash: restoreTransferChunkHash(stalledUnsigned) }, sourceManifest, requesterManifest, '3', verifier)).toBe(false)

    const second = await createRestoreTransferChunk(source, requesterManifest, first.next, '3', 1)
    expect(second).toMatchObject({ events: [], objects: [object], keyWraps: [wrap] })
    expect(second.next).toBeUndefined()
    expect(await verifyRestoreTransferChunk(second, sourceManifest, requesterManifest, '3', verifier)).toBe(true)
  })

  test('rejects tampered frames before the caller can commit them', async () => {
    const manifest = buildVaultManifest(identityId, [], [], '2026-08-21T00:00:00.000Z')
    const source: RestoreTransferSource = {
      async manifest() { return manifest }, async readEvents() { return [] }, async readObjects() { return [] }, async readCurrentEpochWraps() { return [] },
    }
    const chunk = await createRestoreTransferChunk(source, manifest, undefined, '1')
    const verifier = { eventVerifier: signer, async verifyCurrentEpochWrap() { return true } }
    expect(await verifyRestoreTransferChunk({ ...chunk, chunkHash: 'sha256:bad' }, manifest, manifest, '1', verifier)).toBe(false)
  })
})
