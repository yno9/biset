// IndexedDbMlsKeyPackageStore.clear() removes all locally retained private
// KeyPackage halves when an explicit reset is requested.
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { IndexedDbMlsKeyPackageStore } from '../../src/mls/keypackage-store.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'

const DATABASE_NAME = 'biset-mls-keypackages'
const STORE_NAME = 'own-key-packages'
const device = await mlsDeviceFixture('did:web:alice.example')

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

function countRows(): Promise<number> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DATABASE_NAME)
    open.onsuccess = () => {
      const db = open.result
      const request = db.transaction([STORE_NAME], 'readonly').objectStore(STORE_NAME).count()
      request.onsuccess = () => { db.close(); resolve(request.result) }
      request.onerror = () => { db.close(); reject(request.error) }
    }
    open.onerror = () => reject(open.error)
  })
}

describe('IndexedDbMlsKeyPackageStore.clear', () => {
  test('empties the pool', async () => {
    const store = new IndexedDbMlsKeyPackageStore()
    const minted = await store.mint(device.kid, device.credential, device.signaturePrivateKey, 3)
    expect(minted).toHaveLength(3)
    expect(await countRows()).toBe(3)

    await store.clear()

    expect(await countRows()).toBe(0)
    store.close()
  })

  test('is safe to call on an already-empty pool', async () => {
    const store = new IndexedDbMlsKeyPackageStore()
    await expect(store.clear()).resolves.toBeUndefined()
    store.close()
  })
})
