// PLAN.md §3.1's "browser restart, partial write, migration failure の test
// harness" for `IndexedDbVaultStore` -- the one store class no other test
// file exercises against real IndexedDB (everything else in this suite uses
// hand-written memory fakes, which cannot demonstrate that IndexedDB's own
// transaction atomicity and unique-key constraint actually back the
// dedup/durability guarantees `store.ts`'s doc comments claim). `fake-indexeddb`
// gives a spec-accurate `indexedDB`/`IDBKeyRange` in Bun without a browser --
// its per-database-name registry persists independently of any one
// `IDBDatabase` connection, which is exactly what "close the tab, reopen the
// app" durability requires simulating.
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { IndexedDbVaultStore, type IngressVaultCommit, type LocalVaultMutationCommit } from '../../src/client/store/vault/store.ts'
import { createVaultEvent, type VaultEventSigner } from '../../src/client/store/vault/events.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/client/store/vault/objects.ts'
import { sha256Bytes } from '../../src/shared/protocol/canonical.ts'
import type { IngressAckV1 } from '../../src/shared/protocol/ingress.ts'

// Must match DATABASE_NAME/DATABASE_VERSION in src/client/store/vault/store.ts -- not
// exported, so this test's own knowledge of the schema has to stay in sync
// by hand if that module ever renames/re-versions it.
const DATABASE_NAME = 'biset-vault-core'
const CURRENT_VERSION = 10

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = { deviceId: 'device-a', async sign() { return new Uint8Array([7]) }, async verify(_d, _b, sig) { return sig[0] === 7 } }

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

async function buildIngressCommit(ingressId: string): Promise<IngressVaultCommit> {
  const object = await encryptVaultObject(createSegmentKey(), { segmentId: 'segment-1', plaintext: new Uint8Array([1, 2, 3]), aad: new Uint8Array([9]) })
  const event = await createVaultEvent({
    identityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add', targetIds: ['msg-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-24T00:00:00.000Z',
  }, signer)
  const ack: IngressAckV1 = {
    version: 1, ingressId, protectedPayloadHash: new Uint8Array([1]), recipientDeviceId: 'device-a',
    vaultEventId: event.id, checkpointId: 'checkpoint-1', ackedAt: '2026-08-24T00:00:00.000Z', signature: new Uint8Array([2]),
  }
  return {
    identityId,
    receipt: { identityId, ingressId, protectedPayloadHash: new Uint8Array([1]), vaultEventId: event.id, checkpointId: 'checkpoint-1', committedAt: '2026-08-24T00:00:00.000Z' },
    objects: [{ ...object, identityId }],
    events: [event],
    projection: { emails: [] },
    jmapState: { state: 'state-1' },
    ackOutbox: { identityId, ingressId, ack, attempts: 0, createdAt: '2026-08-24T00:00:00.000Z' },
  }
}

async function buildLocalMutationCommit(eventId2Suffix: string): Promise<LocalVaultMutationCommit> {
  const object = await encryptVaultObject(createSegmentKey(), { segmentId: 'segment-1', plaintext: new Uint8Array([4, 5, 6]), aad: new Uint8Array([8]) })
  const event = await createVaultEvent({
    identityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.tombstone', targetIds: [`msg-${eventId2Suffix}`], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-24T00:00:00.000Z',
  }, signer)
  const payload = new Uint8Array([9, 9, 9])
  return {
    identityId,
    objects: [{ ...object, identityId }],
    events: [event],
    projection: { emails: [] },
    jmapState: { state: 'state-local-1' },
    deliveryOutbox: { identityId, entryId: event.id, payload, payloadHash: sha256Bytes(payload), createdAt: '2026-08-24T00:00:00.000Z', attempts: 0 },
  }
}

describe('IndexedDbVaultStore durability', () => {
  test('committed objects/events/projection survive closing and reopening the store (simulated browser restart)', async () => {
    const first = await IndexedDbVaultStore.open()
    const commit = await buildIngressCommit('ingress-1')
    expect(await first.commitIngress(commit)).toBe('committed')
    first.close()

    // A fresh connection -- the same code path `main.ts`'s bootClient takes
    // on every page load -- must see everything the closed connection wrote.
    const second = await IndexedDbVaultStore.open()
    const objects = await second.readVaultObjects(identityId)
    const events = await second.readVaultEvents(identityId)
    const projection = await second.readProjection(identityId)
    expect(objects).toHaveLength(1)
    expect(objects[0]!.objectId).toBe(commit.objects[0]!.objectId)
    expect(events).toHaveLength(1)
    expect(events[0]!.id).toBe(commit.events[0]!.id)
    expect(projection).toEqual({ emails: [] })
    second.close()
  })

  test("a crash between the durable commit and the network ACK send leaves the ACK durably queued, not lost", async () => {
    // ingestIngress (vault/ingress-ingest.ts) commits the receipt/objects/
    // events/projection AND the ackOutbox row in one IndexedDB transaction,
    // strictly before anything sends the ACK over the network -- so a crash
    // in that window must never lose the ACK: it has to still be sitting in
    // the durable outbox for the retry loop to flush on next boot.
    const first = await IndexedDbVaultStore.open()
    const commit = await buildIngressCommit('ingress-crash')
    expect(await first.commitIngress(commit)).toBe('committed')
    first.close()

    const second = await IndexedDbVaultStore.open()
    const outbox = await second.readIngressAckOutbox(identityId, 'device-a')
    expect(outbox).toHaveLength(1)
    expect(outbox[0]!.ingressId).toBe('ingress-crash')
    expect(outbox[0]!.ack.vaultEventId).toBe(commit.events[0]!.id)
    expect(outbox[0]!.attempts).toBe(0)

    // And local durable state (the whole point of "ACK 後は local state が
    // 必ず存在する") is there too, independent of whether the network send
    // ever happens.
    expect(await second.readVaultObjects(identityId)).toHaveLength(1)
    expect(await second.readVaultEvents(identityId)).toHaveLength(1)

    // Once the retry loop actually sends it and gets a response, the outbox
    // entry is removed -- also durable across a further restart.
    await second.removeIngressAckOutbox(identityId, 'ingress-crash')
    second.close()
    const third = await IndexedDbVaultStore.open()
    expect(await third.readIngressAckOutbox(identityId, 'device-a')).toEqual([])
    third.close()
  })

  test('a repeated ingress ID commits its objects/events only once, enforced by the real unique-key constraint', async () => {
    const store = await IndexedDbVaultStore.open()
    const commit = await buildIngressCommit('ingress-dup')
    expect(await store.commitIngress(commit)).toBe('committed')
    // Same ingressId, same records -- a retry after a lost ACK, exactly the
    // scenario the ingressReceipts store's own keyPath uniqueness is there
    // to make safe. A memory fake could accept a "committed" outcome twice
    // without ever proving the underlying constraint fires; this exercises
    // the real one.
    expect(await store.commitIngress(commit)).toBe('already-committed')
    const objects = await store.readVaultObjects(identityId)
    const events = await store.readVaultEvents(identityId)
    expect(objects).toHaveLength(1)
    expect(events).toHaveLength(1)
    store.close()
  })

  test('a repeated local mutation commit (event.id unchanged) commits only once, enforced by the real unique-key constraint', async () => {
    // PLAN.md §3.2's "duplicate event" -- commitLocalMutation is the write
    // path VaultBackedLocalJmapMutationSink uses for the client's OWN
    // mutations (not ingress), and relies on the exact same vault_events
    // unique keyPath (`.add()`, not `.put()`) to make a retry after a lost
    // response idempotent. commitIngress's own dedup is already covered by
    // the test above; this proves the local-mutation path has the same
    // real-constraint guarantee, not just a memory-fake approximation.
    const store = await IndexedDbVaultStore.open()
    const commit = await buildLocalMutationCommit('dup')
    expect(await store.commitLocalMutation(commit)).toBe('committed')
    expect(await store.commitLocalMutation(commit)).toBe('already-committed')
    const events = await store.readVaultEvents(identityId)
    const objects = await store.readVaultObjects(identityId)
    expect(events).toHaveLength(1)
    expect(objects).toHaveLength(1)
    store.close()
  })

  test('the credential event reader includes persisted private contact-key records', async () => {
    const store = await IndexedDbVaultStore.open()
    const object = await encryptVaultObject(createSegmentKey(), { segmentId: 'segment-contact', plaintext: new Uint8Array([1]), aad: new Uint8Array([2]) })
    const event = await createVaultEvent({
      identityId,
      actorDeviceId: 'device-a',
      actorSeq: 1,
      kind: 'contact-key.set',
      targetIds: ['contact-key:bob:peer-kid'],
      objectRefs: [object.objectId],
      parents: [],
      createdAt: '2026-08-27T00:00:00.000Z',
    }, signer)
    const payload = new Uint8Array([3])
    await store.commitLocalMutation({
      identityId,
      objects: [{ ...object, identityId }],
      events: [event],
      projection: { emails: [] },
      jmapState: { state: 'contact-state' },
      deliveryOutbox: { identityId, entryId: event.id, payload, payloadHash: sha256Bytes(payload), createdAt: event.createdAt, attempts: 0 },
    })

    expect(await store.readCredentialEvents(identityId)).toMatchObject([{ kind: 'contact-key.set', id: event.id }])
    store.close()
  })

  test('two different ingress IDs both commit and both persist', async () => {
    const store = await IndexedDbVaultStore.open()
    expect(await store.commitIngress(await buildIngressCommit('ingress-a'))).toBe('committed')
    expect(await store.commitIngress(await buildIngressCommit('ingress-b'))).toBe('committed')
    const events = await store.readVaultEvents(identityId)
    expect(events).toHaveLength(2)
    store.close()
  })

  test('upgrading an older schema (missing the v5/v6 stores) preserves existing data and adds the new stores', async () => {
    // Simulate a device whose IndexedDB was last written by a pre-v5 build:
    // every store EXCEPT vault_restore_transfer_state, opened at version 4.
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, 4)
      request.onupgradeneeded = () => {
        const database = request.result
        for (const [name, keyPath] of [
          ['vault_ingress_receipts', ['identityId', 'ingressId']],
          ['vault_objects', ['identityId', 'objectId']],
          ['vault_events', ['identityId', 'id']],
          ['vault_chunks', ['identityId', 'objectId', 'chunkIndex']],
          ['vault_segments', ['identityId', 'segmentId']],
          ['vault_key_wraps', ['identityId', 'segmentId', 'recipientEpoch']],
          ['vault_manifests', 'identityId'],
          ['vault_projection', 'identityId'],
          ['vault_jmap_state', 'identityId'],
          ['vault_outbox', ['identityId', 'ingressId']],
          ['vault_delivery_outbox', ['identityId', 'entryId']],
          ['vault_delivery_receipts', ['identityId', 'recipientDeviceId', 'seq']],
          ['vault_delivery_ack_outbox', ['identityId', 'recipientDeviceId', 'seq']],
          ['vault_delivery_state', ['identityId', 'deviceId']],
          ['vault_restore_state', ['identityId', 'deviceId']],
          ['vault_restore_offer_outbox', ['identityId', 'requestId', 'responderDeviceId']],
          ['transport_status', ['identityId', 'outboundEventId']],
          // vault_restore_transfer_state and didcomm_transport_outbox are
          // deliberately omitted -- the v5 and v6 additions. (v7/v8 added
          // the since-retired Coordinator binding stores, and v9 added
          // nothing new to the schema -- both are migration-behavior-only
          // version bumps now, not store additions.)
        ] as const) {
          database.createObjectStore(name, { keyPath: keyPath as string | string[] })
        }
      }
      request.onsuccess = () => { request.result.close(); resolve() }
      request.onerror = () => reject(request.error)
    })
    const legacyWrite = await new Promise<void>((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, 4)
      request.onsuccess = () => {
        const database = request.result
        const tx = database.transaction('vault_objects', 'readwrite')
        tx.objectStore('vault_objects').put({ identityId, objectId: 'legacy-object', segmentId: 'segment-1', nonce: new Uint8Array([1]), ciphertext: new Uint8Array([2]), ciphertextHash: new Uint8Array([3]), plaintextLength: 1, aad: new Uint8Array([4]) })
        tx.oncomplete = () => { database.close(); resolve() }
        tx.onerror = () => reject(tx.error)
      }
      request.onerror = () => reject(request.error)
    })
    void legacyWrite

    // Now open through IndexedDbVaultStore, which requests CURRENT_VERSION --
    // this is a real IDBOpenDBRequest upgrade, not a fresh database.
    const store = await IndexedDbVaultStore.open()
    const objects = await store.readVaultObjects(identityId)
    expect(objects.map(o => o.objectId)).toEqual(['legacy-object'])

    // The v6 DIDComm transport outbox was created by the same upgrade.
    expect(await store.readDidCommOutbox(identityId)).toEqual([])
    store.close()

    // And the database really did land on the current version, not still on 4.
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME)
      request.onsuccess = () => { expect(request.result.version).toBe(CURRENT_VERSION); request.result.close(); resolve() }
      request.onerror = () => reject(request.error)
    })
  })
})
