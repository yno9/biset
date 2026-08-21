import { describe, expect, test } from 'bun:test'
import { createVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/vault/objects.ts'
import { createRestoreTransferChunk, type RestoreTransferSource } from '../../src/vault/restore-transfer.ts'
import { receiveRestoreTransferChunk, type RestoreTransferChunkCommit, type RestoreTransferReceiverStore, type RestoreTransferSessionV1 } from '../../src/vault/restore-transfer-receiver.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = { deviceId: 'device-a', async sign() { return new Uint8Array([7]) }, async verify(_device, _bytes, signature) { return signature[0] === 7 } }

class MemoryReceiverStore implements RestoreTransferReceiverStore {
  session?: RestoreTransferSessionV1
  commits: RestoreTransferChunkCommit[] = []
  async readRestoreTransferSession() { return this.session }
  async commitRestoreTransferChunk(input: RestoreTransferChunkCommit) { this.commits.push(input); this.session = input.session }
}

describe('restore transfer receiver', () => {
  test('commits only verified sequential frames and makes the final retry idempotent', async () => {
    const object = await encryptVaultObject(createSegmentKey(), { segmentId: 'segment-1', plaintext: new Uint8Array([1]), aad: new Uint8Array([2]) })
    const event = await createVaultEvent({ identityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add', targetIds: ['message-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-21T00:00:00.000Z' }, signer)
    const sourceManifest = buildVaultManifest(identityId, [event.id], [object.objectId], '2026-08-21T00:00:00.000Z')
    const requesterManifest = buildVaultManifest(identityId, [], [], '2026-08-21T00:00:00.000Z')
    const wrap = { version: 1 as const, identityId, selfGroupId: 'self-1', segmentId: 'segment-1', sourceEpoch: '2', recipientEpoch: '3', nonce: new Uint8Array([1]), aad: new Uint8Array([2]), wrappedSegmentKey: new Uint8Array([3]), grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([4]) }
    const source: RestoreTransferSource = {
      async manifest() { return sourceManifest },
      async readEvents(_identity, ids) { return ids.includes(event.id) ? [event] : [] },
      async readObjects(_identity, ids) { return ids.includes(object.objectId) ? [object] : [] },
      async readCurrentEpochWraps(_identity, segments) { return segments.includes('segment-1') ? [wrap] : [] },
    }
    const verifier = { eventVerifier: signer, async verifyCurrentEpochWrap() { return true } }
    const first = await createRestoreTransferChunk(source, requesterManifest, undefined, '3', 1)
    const second = await createRestoreTransferChunk(source, requesterManifest, first.next, '3', 1)
    const store = new MemoryReceiverStore()
    expect((await receiveRestoreTransferChunk(store, 'device-c', first, sourceManifest, requesterManifest, '3', verifier)).kind).toBe('committed')
    await expect(receiveRestoreTransferChunk(store, 'device-c', first, sourceManifest, requesterManifest, '3', verifier)).rejects.toThrow('out of order')
    expect((await receiveRestoreTransferChunk(store, 'device-c', second, sourceManifest, requesterManifest, '3', verifier)).kind).toBe('committed')
    expect((await receiveRestoreTransferChunk(store, 'device-c', second, sourceManifest, requesterManifest, '3', verifier)).kind).toBe('duplicate')
    expect(store.commits).toHaveLength(2)
    expect(store.session).toMatchObject({ completed: true, lastChunkHash: second.chunkHash })
  })
})
