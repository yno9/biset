// identity/webvh/adopt-move.ts: the passive counterpart to move.ts. A
// device that did NOT perform a domain move still has to notice one
// happened and keep its own IdentityRecord/self-group row pointed at the
// identity's current location -- otherwise every future write it makes
// (add device, revoke, routing publish) would target the stale old
// location instead (identity/webvh/move.ts's own header describes the
// permanent log fork/silently-ineffective-revocation that causes).
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { migrateWebvhLocation } from '../../src/identity/webvh/migrate.ts'
import { encodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { multikeyHashBase58 } from '../../src/identity/webvh/hash.ts'
import { adoptPendingMove } from '../../src/identity/webvh/adopt-move.ts'
import { IndexedDbIdentityRecordStore, type IdentityRecord } from '../../src/identity/record-store.ts'
import { IndexedDbVaultStore } from '../../src/vault/store.ts'
import { IndexedDbMlsSelfGroupStore } from '../../src/mls/store.ts'
import { IndexedDbMlsKeyPackageStore } from '../../src/mls/keypackage-store.ts'
import { createMlsGroup, generateOwnKeyPackage } from '../../src/mls/group.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'

afterEach(async () => {
  for (const name of ['biset-identity', 'biset-vault-core', 'biset-mls-self-group', 'biset-mls-keypackages']) {
    await new Promise<void>(resolve => {
      const request = indexedDB.deleteDatabase(name)
      request.onsuccess = () => resolve()
      request.onerror = () => resolve()
      request.onblocked = () => resolve()
    })
  }
})

describe('adoptPendingMove', () => {
  test('adopts a domain move a sibling device performed: rewrites the record and re-keys the self-group row', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const anchor = fakeAnchor()
    const currentSparePrivateKey = ed25519.utils.randomSecretKey()
    const currentSparePublicKey = ed25519.getPublicKey(currentSparePrivateKey)
    const currentSpareHash = multikeyHashBase58(encodeMultikey(currentSparePublicKey))

    const { did: oldDid } = await createGenesis({
      domain: 'move-src.example', rootPrivateKey, rootPublicKey,
      nextKeyHash: currentSpareHash, fetch: anchor.fetch,
    })
    const device = await mlsDeviceFixture(oldDid, rootPrivateKey)
    const deviceKid = device.kid
    const record: IdentityRecord = {
      did: oldDid, rootPublicKey: '', rootPrivateKey: '', deviceKid, didCommKid: `${oldDid}#k1`,
    }
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(new Uint8Array([1, 2, 3, 4]), kp)

    const recordStore = new IndexedDbIdentityRecordStore()
    const vaultStore = await IndexedDbVaultStore.open()
    const selfGroupStore = new IndexedDbMlsSelfGroupStore()
    const keyPackageStore = new IndexedDbMlsKeyPackageStore()
    const realFetch = globalThis.fetch
    try {
      await recordStore.put(record)
      await selfGroupStore.save(oldDid, 'group-1', state)

      const nextSparePrivateKey = ed25519.utils.randomSecretKey()
      const nextKeyHash = multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(nextSparePrivateKey)))
      const { newDid } = await migrateWebvhLocation({
        oldDid, newDomain: 'move-dst.example',
        signingPrivateKey: currentSparePrivateKey, signingPublicKey: currentSparePublicKey,
        nextKeyHash, fetch: anchor.fetch,
      })

      globalThis.fetch = anchor.fetch
      const adopted = await adoptPendingMove({ recordStore, record, vaultStore, selfGroupStore, keyPackageStore })

      expect(adopted.did).toBe(newDid)
      expect(adopted.deviceKid).toBe(deviceKid)
      expect(adopted.didCommKid).toBe(`${newDid}#k1`)

      expect(await recordStore.get(oldDid)).toBeUndefined()
      expect(await recordStore.get(newDid)).toEqual(adopted)

      expect(await selfGroupStore.load(oldDid)).toBeUndefined()
      const movedGroup = await selfGroupStore.load(newDid)
      expect(movedGroup?.selfGroupId).toBe('group-1')
      expect(movedGroup?.state).toEqual(state)
    } finally {
      globalThis.fetch = realFetch
      recordStore.close()
      vaultStore.close()
      selfGroupStore.close()
      keyPackageStore.close()
    }
  })

  test('is a no-op when the identity has not moved', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const anchor = fakeAnchor()
    const { did } = await createGenesis({ domain: 'no-move.example', rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    const record: IdentityRecord = { did, rootPublicKey: '', rootPrivateKey: '' }

    const recordStore = new IndexedDbIdentityRecordStore()
    const vaultStore = await IndexedDbVaultStore.open()
    const selfGroupStore = new IndexedDbMlsSelfGroupStore()
    const keyPackageStore = new IndexedDbMlsKeyPackageStore()
    const realFetch = globalThis.fetch
    try {
      await recordStore.put(record)
      globalThis.fetch = anchor.fetch
      const result = await adoptPendingMove({ recordStore, record, vaultStore, selfGroupStore, keyPackageStore })
      expect(result).toBe(record)
    } finally {
      globalThis.fetch = realFetch
      recordStore.close()
      vaultStore.close()
      selfGroupStore.close()
      keyPackageStore.close()
    }
  })

  test('returns the record unchanged, without throwing, when resolution fails right now', async () => {
    const record: IdentityRecord = {
      did: 'did:webvh:deadbeef:unreachable.example', rootPublicKey: 'aa', rootPrivateKey: 'bb',
    }
    const recordStore = new IndexedDbIdentityRecordStore()
    const vaultStore = await IndexedDbVaultStore.open()
    const selfGroupStore = new IndexedDbMlsSelfGroupStore()
    const keyPackageStore = new IndexedDbMlsKeyPackageStore()
    const realFetch = globalThis.fetch
    try {
      globalThis.fetch = (async () => new Response('', { status: 404 })) as typeof fetch
      const result = await adoptPendingMove({ recordStore, record, vaultStore, selfGroupStore, keyPackageStore })
      expect(result).toBe(record)
    } finally {
      globalThis.fetch = realFetch
      recordStore.close()
      vaultStore.close()
      selfGroupStore.close()
      keyPackageStore.close()
    }
  })
})
