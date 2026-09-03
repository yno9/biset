// PLAN.md §7's vault UI needs a ready LocalJmapReadModel for an identity --
// buildLocalJmapReadModel (identity/bootstrap.ts) is the new boundary that
// assembles it from IndexedDbVaultStore + a real MLS self group. Confirms
// end to end, against real IndexedDB (fake-indexeddb) and a real MLS self
// group: snapshot() reflects a committed mail message, and download()
// decrypts the same raw RFC 5322 bytes the message was written with.
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { buildLocalJmapProjectionRebuild, buildLocalJmapReadModel, buildVaultCryptoBoundary } from '../../src/identity/bootstrap.ts'
import { createMlsGroup } from '../../src/mls/group.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'
import { buildMailMessageAdd } from '../../src/vault/mail-message.ts'
import { IndexedDbVaultStore } from '../../src/vault/store.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'

const DATABASE_NAME = 'biset-vault-core'
const identityId = 'did:web:alice.example'
const selfGroupId = 'test-self-group'

function memorySelfGroupStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

describe('buildLocalJmapReadModel', () => {
  test('reflects a committed mail message and decrypts its raw RFC 5322 blob, through real IndexedDB and a real MLS self group', async () => {
    const device = await mlsDeviceFixture(identityId)
    const deviceKid = device.kid
    const kp = device.own
    const state = await createMlsGroup(new TextEncoder().encode(selfGroupId), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupId, state)

    const store = await IndexedDbVaultStore.open()
    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const boundary = buildVaultCryptoBoundary(store, store, selfGroupStore, record)
    const segment = await boundary.activeSegment()

    const rawRfc5322 = new TextEncoder().encode('Subject: hi\r\n\r\nhello from the vault')
    const { metadataObject, rawRfc5322Object, event } = await buildMailMessageAdd(
      {
        email: { id: 'msg-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-24T00:00:00.000Z' },
        rawRfc5322,
      },
      { identityId, actorDeviceId: deviceKid, actorSeq: 1, parents: [], segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt: '2026-08-24T00:00:00.000Z' },
      boundary.signer,
    )
    // Raw records committed directly (no deliveryOutbox/projection needed --
    // commitRecoveryArchive's shape is a convenient atomic "just the
    // records" writer, same as any other seeding path would use); the
    // projection itself comes from rebuild, same as every restore path in
    // this codebase already does.
    await store.commitRecoveryArchive({
      identityId,
      events: [{ ...event, identityId }],
      objects: [{ ...metadataObject, identityId }, { ...rawRfc5322Object, identityId }],
      keyWraps: segment.keyWraps,
    })
    await buildLocalJmapProjectionRebuild(store, store, store, selfGroupStore, identityId)()

    const readModel = buildLocalJmapReadModel(store, selfGroupStore, identityId)
    const snapshot = await readModel.snapshot()
    expect(snapshot.emails).toHaveLength(1)
    expect(snapshot.emails[0]).toMatchObject({ id: 'msg-1', threadId: 'thread-1', blobId: rawRfc5322Object.objectId })

    const downloaded = await readModel.download(rawRfc5322Object.objectId)
    expect(downloaded).toEqual(rawRfc5322)

    store.close()
  })
})
