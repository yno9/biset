// IndexedDbMlsSelfGroupStore.delete (identity/webvh/move.ts's own
// domain-move support): after mls/self-group.ts's migrateSelfGroupCredential
// has already saved this identity's migrated state under the NEW
// identityId, the now-stale row still sitting under the OLD one needs to
// be dropped explicitly.
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { createMlsGroup, generateOwnKeyPackage } from '../../src/client/mimi/group.ts'
import { IndexedDbMlsSelfGroupStore } from '../../src/client/mimi/store.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'

const DATABASE_NAME = 'biset-mls-self-group'
const oldId = 'did:webvh:2222222222222222222222222222222222222222222222:old.example'
const device = await mlsDeviceFixture(oldId)

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

describe('IndexedDbMlsSelfGroupStore.delete', () => {
  test('removes the row for the given identityId', async () => {
    const own = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(crypto.getRandomValues(new Uint8Array(32)), own)
    const store = new IndexedDbMlsSelfGroupStore()
    await store.save(oldId, 'self-group-scid-hash', state)
    expect(await store.load(oldId)).toBeDefined()

    await store.delete(oldId)

    expect(await store.load(oldId)).toBeUndefined()
    store.close()
  })

  test('is safe to call when there is no row for the given identityId', async () => {
    const store = new IndexedDbMlsSelfGroupStore()
    await expect(store.delete(oldId)).resolves.toBeUndefined()
    store.close()
  })
})
