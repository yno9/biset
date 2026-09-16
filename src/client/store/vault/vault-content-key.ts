import { assertMlsEpoch, type IdentityId, type MlsEpoch } from '../../../protocol/ids.ts'
import type { CurrentVaultEpoch, VaultEpochKeyResolver } from './segment-key-resolver.ts'

/** Stable, public identifier for the Wallet-derived Vault Content Key. */
export const VAULT_CONTENT_KEY_GROUP_ID = 'urn:biset:vault-content-key:v1'
export const VAULT_CONTENT_KEY_PURPOSE = 'biset:vault-content-key:v1'

export function vaultGenerationUrn(generation: MlsEpoch): string {
  assertMlsEpoch(generation)
  return `${VAULT_CONTENT_KEY_GROUP_ID}:${generation}`
}

export function parseVaultGenerationUrn(value: string): MlsEpoch {
  if (typeof value !== 'string' || !value.startsWith(`${VAULT_CONTENT_KEY_GROUP_ID}:`)) {
    throw new TypeError('Vault generation service endpoint is invalid')
  }
  const generation = value.slice(VAULT_CONTENT_KEY_GROUP_ID.length + 1)
  assertMlsEpoch(generation)
  return generation
}

/** The session boundary deliberately exposes copies, never its stored VCKs. */
export interface VaultContentKeyProvider {
  currentGeneration(identityId: IdentityId): Promise<MlsEpoch>
  keyForGeneration(identityId: IdentityId, generation: MlsEpoch): Promise<Uint8Array | undefined>
}

/**
 * Adapts Wallet-derived VCKs to the existing epoch-key abstraction.  The
 * storage and checkpoint layers consequently do not know whether their KEK
 * originated in MLS or in the Wallet.
 */
export class WalletDerivedVaultKeyResolver implements VaultEpochKeyResolver {
  constructor(private readonly keys: VaultContentKeyProvider) {}

  async currentVaultEpoch(identityId: IdentityId): Promise<CurrentVaultEpoch> {
    const epoch = await this.keys.currentGeneration(identityId)
    assertMlsEpoch(epoch)
    return { selfGroupId: VAULT_CONTENT_KEY_GROUP_ID, epoch }
  }

  async deriveVaultEpochKey(identityId: IdentityId, selfGroupId: string, epoch: MlsEpoch): Promise<Uint8Array> {
    if (selfGroupId !== VAULT_CONTENT_KEY_GROUP_ID) throw new Error('Vault Content Key group does not match this Wallet session')
    assertMlsEpoch(epoch)
    const key = await this.keys.keyForGeneration(identityId, epoch)
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error(`Vault Content Key generation ${epoch} is unavailable; reconnect your did.md Wallet`)
    }
    return key.slice()
  }
}
