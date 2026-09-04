import { describe, expect, test } from 'bun:test'
import { createVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/vault/objects.ts'
import { createRecoveryArchiveSnapshot } from '../../src/vault/recovery-archive-export.ts'
import { equalBytes } from '../../src/shared/protocol/canonical.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('recovery archive export', () => {
  test('takes every local ciphertext/event and only the SegmentKeys needed to reopen them', async () => {
    const firstKey = createSegmentKey()
    const secondKey = createSegmentKey()
    const first = await encryptVaultObject(firstKey, { segmentId: 'segment-1', plaintext: new Uint8Array([1]), aad: new Uint8Array([2]) })
    const second = await encryptVaultObject(secondKey, { segmentId: 'segment-2', plaintext: new Uint8Array([3]), aad: new Uint8Array([4]) })
    const event = await createVaultEvent({ identityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add', targetIds: ['message-1'], objectRefs: [first.objectId, second.objectId], parents: [], createdAt: '2026-08-22T00:00:00.000Z' }, signer)
    const resolved: string[] = []
    const snapshot = await createRecoveryArchiveSnapshot(
      { async readVaultEvents() { return [{ ...event, identityId }] }, async readVaultObjects() { return [{ ...second, identityId }, { ...first, identityId }] } },
      { async resolveSegmentKey(_identityId, segmentId) { resolved.push(segmentId); return segmentId === 'segment-1' ? firstKey.slice() : secondKey.slice() } },
      identityId,
      '2026-08-22T01:00:00.000Z',
    )
    expect(snapshot.manifest.eventIds).toEqual([event.id])
    expect(snapshot.manifest.objectIds).toEqual([first.objectId, second.objectId].sort())
    expect(snapshot.segmentKeys.map(value => value.segmentId)).toEqual(['segment-1', 'segment-2'])
    expect(resolved).toEqual(['segment-1', 'segment-2'])
  })

  test('does not leave resolver-returned SegmentKeys live after the snapshot was copied', async () => {
    const segmentKey = createSegmentKey()
    const object = await encryptVaultObject(segmentKey, { segmentId: 'segment-1', plaintext: new Uint8Array([1]), aad: new Uint8Array([2]) })
    const returned = segmentKey.slice()
    const snapshot = await createRecoveryArchiveSnapshot(
      { async readVaultEvents() { return [] }, async readVaultObjects() { return [{ ...object, identityId }] } },
      { async resolveSegmentKey() { return returned } }, identityId, '2026-08-22T01:00:00.000Z',
    )
    expect(returned).toEqual(new Uint8Array(32))
    expect(snapshot.segmentKeys[0]?.key).toEqual(segmentKey)
  })
})
