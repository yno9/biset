// IndexedDbVaultStore.rekeyIdentity (identity/webvh/move.ts's own domain-move
// support): every store is keyed by identityId, so a domain move has to move
// every row from the old did:webvh string to the new one, not just update
// `identity.did` in memory. Covers both single-field keyPath stores
// (projection) and compound ones (objects/events/deliveryOutbox) -- the two
// shapes rekeyIdentity's generic KEY_PATHS-driven logic has to handle
// identically.
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { IndexedDbVaultStore, type IngressVaultCommit } from '../../src/vault/store.ts'
import { createVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/vault/objects.ts'
import type { IngressAckV1 } from '../../src/protocol/ingress.ts'

const DATABASE_NAME = 'biset-vault-core'
const oldId = 'did:webvh:2222222222222222222222222222222222222222222222:old.example'
const newId = 'did:webvh:2222222222222222222222222222222222222222222222:new.example'
const signer: VaultEventSigner = { deviceId: 'device-a', async sign() { return new Uint8Array([7]) }, async verify(_d, _b, sig) { return sig[0] === 7 } }

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

async function buildIngressCommit(identityId: string): Promise<IngressVaultCommit> {
  const object = await encryptVaultObject(createSegmentKey(), { segmentId: 'segment-1', plaintext: new Uint8Array([1, 2, 3]), aad: new Uint8Array([9]) })
  const event = await createVaultEvent({
    identityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add', targetIds: ['msg-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-26T00:00:00.000Z',
  }, signer)
  const ack: IngressAckV1 = {
    version: 1, ingressId: 'ingress-1', protectedPayloadHash: new Uint8Array([1]), recipientDeviceId: 'device-a',
    vaultEventId: event.id, checkpointId: 'checkpoint-1', ackedAt: '2026-08-26T00:00:00.000Z', signature: new Uint8Array([2]),
  }
  return {
    identityId,
    receipt: { identityId, ingressId: 'ingress-1', protectedPayloadHash: new Uint8Array([1]), vaultEventId: event.id, checkpointId: 'checkpoint-1', committedAt: '2026-08-26T00:00:00.000Z' },
    objects: [{ ...object, identityId }],
    events: [event],
    projection: { emails: ['e1'] },
    jmapState: { state: 'state-1' },
    ackOutbox: { identityId, ingressId: 'ingress-1', ack, attempts: 0, createdAt: '2026-08-26T00:00:00.000Z' },
  }
}

describe('IndexedDbVaultStore.rekeyIdentity', () => {
  test('moves every row from the old identityId to the new one, across both single- and compound-key stores', async () => {
    const store = await IndexedDbVaultStore.open()
    const commit = await buildIngressCommit(oldId)
    expect(await store.commitIngress(commit)).toBe('committed')

    await store.rekeyIdentity(oldId, newId)

    // Old identity: gone everywhere.
    expect(await store.readVaultObjects(oldId)).toHaveLength(0)
    expect(await store.readVaultEvents(oldId)).toHaveLength(0)
    expect(await store.readProjection(oldId)).toBeUndefined()
    expect(await store.readDeliveryOutbox(oldId)).toHaveLength(0)

    // New identity: everything, byte-for-byte.
    const objects = await store.readVaultObjects(newId)
    const events = await store.readVaultEvents(newId)
    expect(objects).toHaveLength(1)
    expect(objects[0]!.objectId).toBe(commit.objects[0]!.objectId)
    expect(objects[0]!.identityId).toBe(newId)
    expect(events).toHaveLength(1)
    expect(events[0]!.id).toBe(commit.events[0]!.id)
    expect(events[0]!.identityId).toBe(newId)
    expect(await store.readProjection(newId)).toEqual({ emails: ['e1'] })

    store.close()
  })

  test('is a no-op when old and new identityId are the same', async () => {
    const store = await IndexedDbVaultStore.open()
    const commit = await buildIngressCommit(oldId)
    await store.commitIngress(commit)

    await store.rekeyIdentity(oldId, oldId)

    expect(await store.readVaultObjects(oldId)).toHaveLength(1)
    store.close()
  })

  test('survives closing and reopening (the rekey is durable, not just an in-memory effect)', async () => {
    const first = await IndexedDbVaultStore.open()
    const commit = await buildIngressCommit(oldId)
    await first.commitIngress(commit)
    await first.rekeyIdentity(oldId, newId)
    first.close()

    const second = await IndexedDbVaultStore.open()
    expect(await second.readVaultObjects(oldId)).toHaveLength(0)
    expect(await second.readVaultObjects(newId)).toHaveLength(1)
    second.close()
  })
})
