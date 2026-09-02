import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { IndexedDbVaultStore, type VaultEventRecord } from '../src/vault/store.ts'

const identityId = 'did:webvh:test:alice.example'
const eventId = 'sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const createdAt = '2026-08-27T00:00:00.000Z'
const event: VaultEventRecord = {
  version: 1,
  id: eventId,
  identityId,
  actorDeviceId: `${identityId}#device-1`,
  actorSeq: 1,
  kind: 'message.add',
  targetIds: ['email-1'],
  objectRefs: [],
  parents: [],
  createdAt,
  signature: new Uint8Array([1]),
}

afterEach(async () => {
  await new Promise<void>(resolve => {
    const request = indexedDB.deleteDatabase('biset-vault-core')
    request.onsuccess = request.onerror = request.onblocked = () => resolve()
  })
})

describe('IndexedDB transport boundaries', () => {
  test('commits a DIDComm outbox row atomically with the local message mutation', async () => {
    const store = await IndexedDbVaultStore.open()
    try {
      await store.commitLocalMutation({
        identityId,
        objects: [],
        events: [event],
        projection: {},
        jmapState: {},
        deliveryOutbox: { identityId, entryId: eventId, payload: new Uint8Array([1]), payloadHash: new Uint8Array([2]), createdAt, attempts: 0 },
        didCommOutbox: [{ identityId, outboundEventId: eventId, emailId: 'email-1', messageId: 'message-1', toDid: 'did:example:bob', createdAt, attempts: 0 }],
      })

      expect(await store.readDidCommOutbox(identityId)).toEqual([{
        identityId, outboundEventId: eventId, emailId: 'email-1', messageId: 'message-1', toDid: 'did:example:bob', createdAt, attempts: 0,
      }])
      await store.noteDidCommOutboxAttempt(identityId, eventId, 'did:example:bob', '2026-08-27T00:00:01.000Z')
      expect((await store.readDidCommOutbox(identityId))[0]).toMatchObject({ attempts: 1, lastAttemptAt: '2026-08-27T00:00:01.000Z' })
      await store.removeDidCommOutbox(identityId, eventId, 'did:example:bob')
      expect(await store.readDidCommOutbox(identityId)).toEqual([])
    } finally {
      store.close()
    }
  })

  test('commits a transport-owned ingress receipt without a core ACK row', async () => {
    const store = await IndexedDbVaultStore.open()
    try {
      await store.commitIngress({
        identityId,
        receipt: { identityId, ingressId: 'mediator-item-1', protectedPayloadHash: new Uint8Array([1]), vaultEventId: eventId, checkpointId: 'checkpoint-1', committedAt: createdAt },
        objects: [], events: [event], projection: {}, jmapState: {},
      })
      expect((await store.readIngressReceipt(identityId, 'mediator-item-1'))?.ingressId).toBe('mediator-item-1')
      expect(await store.readIngressAckOutbox(identityId, event.actorDeviceId)).toEqual([])
    } finally {
      store.close()
    }
  })
})
