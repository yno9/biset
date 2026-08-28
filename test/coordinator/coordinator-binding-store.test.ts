import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { IndexedDbVaultStore, type LocalVaultCoordinatorBindingV1 } from '../../src/vault/store.ts'
import { createVaultMlsGenesis, createVaultMlsJoinCandidate, joinVaultMlsFromWelcome, prepareVaultMlsAdd } from '../../src/mls/vault-group.ts'

const databaseName = 'biset-vault-core'
const identityId = 'did:webvh:binding:anchor.example'
const movedIdentityId = 'did:webvh:binding:new-anchor.example'

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(databaseName)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

describe('local Vault Coordinator binding', () => {
  test('persists the opaque Vault route/group/member key without placing it in Anchor state', async () => {
    const first = await IndexedDbVaultStore.open()
    const binding = await createBinding(identityId)
    await first.writeCoordinatorBinding(binding)
    first.close()

    const second = await IndexedDbVaultStore.open()
    const restored = await second.readCoordinatorBinding(identityId)
    expect(restored).toMatchObject({
      version: 1,
      identityId,
      coordinatorUrl: 'https://coordinator.biset.md',
      localMemberId: binding.localMemberId,
      groupView: { vaultId: binding.groupView.vaultId, groupEpoch: '1' },
    })
    expect(restored?.memberSignaturePrivateKey).toEqual(binding.memberSignaturePrivateKey)
    const originalFirstByte = binding.memberSignaturePrivateKey[0]
    restored!.memberSignaturePrivateKey[0] = 0
    expect((await second.readCoordinatorBinding(identityId))?.memberSignaturePrivateKey[0]).toBe(originalFirstByte)
    second.close()
  })

  test('moves only the Client-local binding when a public DID moves domains', async () => {
    const store = await IndexedDbVaultStore.open()
    const binding = await createBinding(identityId)
    await store.writeCoordinatorBinding(binding)
    await store.rekeyIdentity(identityId, movedIdentityId)
    expect(await store.readCoordinatorBinding(identityId)).toBeUndefined()
    expect(await store.readCoordinatorBinding(movedIdentityId)).toMatchObject({ identityId: movedIdentityId, groupView: { vaultId: binding.groupView.vaultId } })
    store.close()
  })

  test('rejects a local member secret that does not match the accepted group view', async () => {
    const store = await IndexedDbVaultStore.open()
    const binding = await createBinding(identityId)
    binding.memberSignaturePrivateKey = new Uint8Array(32).fill(30)
    await expect(store.writeCoordinatorBinding(binding)).rejects.toThrow('does not match')
    store.close()
  })

  test('persists the one-shot join secret across restart and deletes it atomically with the accepted binding', async () => {
    const firstMember = await createVaultMlsGenesis()
    const candidate = await createVaultMlsJoinCandidate()
    const pendingAdd = await prepareVaultMlsAdd({ encodedState: firstMember.encodedState, groupView: firstMember.groupView, localMemberId: firstMember.memberId, memberSignaturePrivateKey: firstMember.memberSignaturePrivateKey }, candidate.encodedKeyPackage, '1')
    const joined = await joinVaultMlsFromWelcome(candidate, pendingAdd.welcome, pendingAdd.groupView)
    const store = await IndexedDbVaultStore.open()
    await store.writeCoordinatorPendingJoin({ version: 1, identityId, coordinatorUrl: 'https://coordinator.biset.md', vaultId: firstMember.vaultId, memberId: candidate.memberId, encodedKeyPackage: candidate.encodedKeyPackage, initPrivateKey: candidate.ownKeyPackage.privatePackage.initPrivateKey, hpkePrivateKey: candidate.ownKeyPackage.privatePackage.hpkePrivateKey, signaturePrivateKey: candidate.memberSignaturePrivateKey, createdAt: '2026-08-28T03:10:00.000Z', expiresAt: '2026-08-28T03:20:00.000Z' })
    store.close()
    const reopened = await IndexedDbVaultStore.open()
    expect((await reopened.readCoordinatorPendingJoin(identityId))?.memberId).toBe(candidate.memberId)
    const binding: LocalVaultCoordinatorBindingV1 = { version: 1, identityId, coordinatorUrl: 'https://coordinator.biset.md', groupView: pendingAdd.groupView, vaultMlsState: joined.encodedState, localMemberId: candidate.memberId, memberSignaturePrivateKey: joined.memberSignaturePrivateKey, createdAt: '2026-08-28T03:11:00.000Z', updatedAt: '2026-08-28T03:11:00.000Z' }
    await reopened.commitCoordinatorJoin(binding)
    expect(await reopened.readCoordinatorPendingJoin(identityId)).toBeUndefined()
    expect((await reopened.readCoordinatorBinding(identityId))?.localMemberId).toBe(candidate.memberId)
    reopened.close()
    pendingAdd.confirm()
  })
})

async function createBinding(forIdentity: string): Promise<LocalVaultCoordinatorBindingV1> {
  const genesis = await createVaultMlsGenesis()
  return {
    version: 1,
    identityId: forIdentity,
    coordinatorUrl: 'https://coordinator.biset.md',
    vaultMlsState: genesis.encodedState,
    groupView: genesis.groupView,
    localMemberId: genesis.memberId,
    memberSignaturePrivateKey: genesis.memberSignaturePrivateKey,
    createdAt: '2026-08-28T03:00:00.000Z',
    updatedAt: '2026-08-28T03:00:00.000Z',
  }
}
