import { describe, expect, test } from 'bun:test'
import { WalletDerivedVaultKeyResolver, VAULT_CONTENT_KEY_GROUP_ID, parseVaultGenerationUrn, vaultGenerationUrn } from '../../src/client/store/vault/vault-content-key.ts'
import { vaultGenerationFromDidDocument } from '../../src/client/identity/wallet/did-md-oauth.ts'

describe('Wallet-derived Vault Content Key', () => {
  test('round-trips valid uint64 generations and rejects non-canonical values', () => {
    expect(parseVaultGenerationUrn(vaultGenerationUrn('18446744073709551615'))).toBe('18446744073709551615')
    expect(() => parseVaultGenerationUrn(`${VAULT_CONTENT_KEY_GROUP_ID}:01`)).toThrow()
    expect(() => parseVaultGenerationUrn('urn:other:0')).toThrow()
  })

  test('only returns a key from the requested current Wallet generation', async () => {
    const resolver = new WalletDerivedVaultKeyResolver({
      async currentGeneration() { return '3' },
      async keyForGeneration(_identity, generation) { return generation === '3' ? new Uint8Array(32).fill(7) : undefined },
    })
    expect(await resolver.currentVaultEpoch('did:web:alice.example')).toEqual({ selfGroupId: VAULT_CONTENT_KEY_GROUP_ID, epoch: '3' })
    expect(await resolver.deriveVaultEpochKey('did:web:alice.example', VAULT_CONTENT_KEY_GROUP_ID, '3')).toEqual(new Uint8Array(32).fill(7))
    await expect(resolver.deriveVaultEpochKey('did:web:alice.example', VAULT_CONTENT_KEY_GROUP_ID, '2')).rejects.toThrow('reconnect')
    await expect(resolver.deriveVaultEpochKey('did:web:alice.example', 'other', '3')).rejects.toThrow('group')
  })

  test('reads the signed Biset Vault service and treats its absence as uninitialized', () => {
    const did = 'did:webvh:example:alice'
    expect(vaultGenerationFromDidDocument(did, { service: [{ id: '#biset-vault', serviceEndpoint: vaultGenerationUrn('9') }] })).toBe('9')
    expect(vaultGenerationFromDidDocument(did, { service: [{ id: `${did}#biset-vault`, serviceEndpoint: vaultGenerationUrn('10') }] })).toBe('10')
    expect(vaultGenerationFromDidDocument(did, { service: [] })).toBeUndefined()
    expect(() => vaultGenerationFromDidDocument(did, { service: [{ id: '#biset-vault', serviceEndpoint: 'urn:wrong:0' }] })).toThrow()
  })
})
