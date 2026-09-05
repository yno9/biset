import { canonicalBytes } from '../../shared/protocol/canonical.ts'
import { assertMlsEpoch, type MlsEpoch } from '../../shared/protocol/ids.ts'
import type { CurrentVaultEpoch, VaultEpochKeyResolver } from '../store/vault/segment-key-resolver.ts'

export const VAULT_EPOCH_KEY_LABEL = 'biset/vault/epoch-key/v1'
export const VAULT_EPOCH_KEY_LENGTH = 32

/**
 * The only MLS capability that the vault crypto layer needs. An MLS adapter
 * owns group state; this boundary never receives its exporter secret or state
 * encoding and therefore has nowhere to persist either one.
 */
export interface MlsEpochExporter {
  readonly selfGroupId: string
  readonly epoch: MlsEpoch
  exportSecret(label: string, context: Uint8Array, length: number): Promise<Uint8Array>
}

/** The MLS implementation owns the private group state and exposes only its current exporter. */
export interface MlsSelfGroupProvider {
  currentSelfGroup(identityId: string): Promise<MlsEpochExporter>
}

/**
 * Connects the fixed VEK derivation to a live MLS self group without passing
 * MLS state or exporter secrets into the vault store. A commit raced between
 * `currentVaultEpoch` and `deriveVaultEpochKey` is rejected instead of using a
 * key from a different epoch.
 */
export class MlsVaultEpochKeyResolver implements VaultEpochKeyResolver {
  constructor(private readonly groups: MlsSelfGroupProvider) {}

  async currentVaultEpoch(identityId: string): Promise<CurrentVaultEpoch> {
    const group = await this.groups.currentSelfGroup(identityId)
    assertGroup(group)
    return { selfGroupId: group.selfGroupId, epoch: group.epoch }
  }

  async deriveVaultEpochKey(identityId: string, selfGroupId: string, epoch: MlsEpoch): Promise<Uint8Array> {
    const group = await this.groups.currentSelfGroup(identityId)
    assertGroup(group)
    if (group.selfGroupId !== selfGroupId || group.epoch !== epoch) {
      throw new Error('MLS self-group epoch changed; retry vault operation')
    }
    return deriveVaultEpochKey(group)
  }
}

/**
 * Derives the VEK for the adapter's currently accepted self-group epoch. The
 * caller cannot change the label, context, or output size. A different group
 * or epoch necessarily produces a different exporter context.
 */
export async function deriveVaultEpochKey(group: MlsEpochExporter): Promise<Uint8Array> {
  if (!group.selfGroupId) throw new TypeError('MLS self group ID must not be empty')
  assertMlsEpoch(group.epoch)
  const key = await group.exportSecret(
    VAULT_EPOCH_KEY_LABEL,
    vaultEpochKeyContext(group.selfGroupId, group.epoch),
    VAULT_EPOCH_KEY_LENGTH,
  )
  if (!(key instanceof Uint8Array) || key.length !== VAULT_EPOCH_KEY_LENGTH) {
    throw new TypeError('MLS exporter returned an invalid Vault Epoch Key')
  }
  return key.slice()
}

export function vaultEpochKeyContext(selfGroupId: string, epoch: MlsEpoch): Uint8Array {
  if (!selfGroupId) throw new TypeError('MLS self group ID must not be empty')
  assertMlsEpoch(epoch)
  return canonicalBytes({
    label: VAULT_EPOCH_KEY_LABEL,
    selfGroupId,
    epoch,
  })
}

function assertGroup(group: MlsEpochExporter): void {
  if (!group.selfGroupId) throw new TypeError('MLS self group ID must not be empty')
  assertMlsEpoch(group.epoch)
}
