// Verifies the concrete MlsSelfGroupProvider (src/mls/store.ts) end to end:
// a real MLS group's ClientState round-trips through an in-memory
// MlsSelfGroupStateStore (the same contract IndexedDbMlsSelfGroupStore
// implements against IndexedDB, untestable under Bun) and produces a usable
// MlsEpochExporter that the existing Vault Epoch Key boundary
// (mls/vault-epoch.ts) can derive a key from.
import { describe, expect, test } from 'bun:test'
import { createMlsGroup, generateOwnKeyPackage, rekey } from '../../src/client/mimi/group.ts'
import { StoredMlsSelfGroupProvider, type LoadedMlsSelfGroup, type MlsSelfGroupStateStore } from '../../src/client/mimi/store.ts'
import { MlsVaultEpochKeyResolver } from '../../src/client/mimi/vault-epoch.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'

const identityId = 'did:web:alice.example'
const device = await mlsDeviceFixture(identityId)

function memoryStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(identityId, selfGroupId, state) { rows.set(identityId, { selfGroupId, state }) },
    async load(identityId) { return rows.get(identityId) },
  }
}

describe('StoredMlsSelfGroupProvider', () => {
  test('round-trips a real ClientState and exposes its exporter secret', async () => {
    const own = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(crypto.getRandomValues(new Uint8Array(32)), own)
    const store = memoryStore()
    await store.save('did:web:alice.example', 'self-group-alice', state)

    const provider = new StoredMlsSelfGroupProvider(store)
    const exporter = await provider.currentSelfGroup('did:web:alice.example')
    expect(exporter.selfGroupId).toBe('self-group-alice')
    expect(exporter.epoch).toBe('0')

    const key = await exporter.exportSecret('biset/vault/epoch-key/v1', new Uint8Array([1, 2, 3]), 32)
    expect(key).toHaveLength(32)
  })

  test('throws for an identity with no stored self-group state', async () => {
    const provider = new StoredMlsSelfGroupProvider(memoryStore())
    await expect(provider.currentSelfGroup('did:web:nobody.example')).rejects.toThrow('no self-group state')
  })

  test('feeds MlsVaultEpochKeyResolver: VEK changes across a rekey, matches across two reads at the same epoch', async () => {
    const own = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const genesis = await createMlsGroup(crypto.getRandomValues(new Uint8Array(32)), own)
    const store = memoryStore()
    await store.save('did:web:alice.example', 'self-group-alice', genesis)

    const resolver = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(store))
    const before = await resolver.currentVaultEpoch('did:web:alice.example')
    const key1 = await resolver.deriveVaultEpochKey('did:web:alice.example', before.selfGroupId, before.epoch)
    const key1Again = await resolver.deriveVaultEpochKey('did:web:alice.example', before.selfGroupId, before.epoch)
    expect(key1).toEqual(key1Again)

    const { state: rekeyed } = await rekey(genesis)
    await store.save('did:web:alice.example', 'self-group-alice', rekeyed)
    const after = await resolver.currentVaultEpoch('did:web:alice.example')
    expect(BigInt(after.epoch)).toBeGreaterThan(BigInt(before.epoch))
    const key2 = await resolver.deriveVaultEpochKey('did:web:alice.example', after.selfGroupId, after.epoch)
    expect(key2).not.toEqual(key1)

    // A caller holding the pre-rekey epoch is rejected rather than silently
    // handed a key derived from a state it never asked about.
    await expect(resolver.deriveVaultEpochKey('did:web:alice.example', before.selfGroupId, before.epoch)).rejects.toThrow('epoch changed')
  })
})
