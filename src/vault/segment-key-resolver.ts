import type { SegmentId, IdentityId, MlsEpoch } from '../protocol/ids.ts'
import type { SegmentKeyWrapReader } from './store.ts'
import { unwrapSegmentKey, type SegmentKeyWrapVerifier } from './crypto.ts'
import { VAULT_STORAGE_EPOCH, VAULT_STORAGE_GROUP_ID } from './storage-root.ts'

export interface CurrentVaultEpoch {
  selfGroupId: string
  epoch: MlsEpoch
}

/** MLS adapter boundary. VEK output is transient and must not be persisted. */
export interface VaultEpochKeyResolver {
  currentVaultEpoch(identityId: IdentityId): Promise<CurrentVaultEpoch>
  deriveVaultEpochKey(identityId: IdentityId, selfGroupId: string, epoch: MlsEpoch): Promise<Uint8Array>
}

/** Local consumers may resolve a current-epoch SegmentKey without learning a VEK. */
export interface SegmentKeyResolver {
  resolveSegmentKey(identityId: IdentityId, segmentId: SegmentId): Promise<Uint8Array>
}

/**
 * Looks up only the wrap for the current self-group epoch, verifies the
 * grantor signature, and unwraps one SegmentKey in memory. Old epoch wraps
 * are not fallback keys: a new/current-epoch grant is required for restore.
 */
export class StoredSegmentKeyResolver implements SegmentKeyResolver {
  constructor(
    private readonly wraps: SegmentKeyWrapReader,
    private readonly epochs: VaultEpochKeyResolver,
    private readonly signer: SegmentKeyWrapVerifier,
    private readonly storageKek?: Uint8Array,
  ) {}

  async resolveSegmentKey(identityId: IdentityId, segmentId: SegmentId): Promise<Uint8Array> {
    if (this.storageKek) {
      const stable = await this.wraps.readSegmentKeyWrap(identityId, segmentId, VAULT_STORAGE_EPOCH)
      if (stable) {
        if (stable.identityId !== identityId || stable.segmentId !== segmentId || stable.selfGroupId !== VAULT_STORAGE_GROUP_ID || stable.sourceEpoch !== VAULT_STORAGE_EPOCH || stable.recipientEpoch !== VAULT_STORAGE_EPOCH) throw new TypeError('stored Vault storage wrap has invalid metadata')
        // AES-GCM under the root-derived secret authenticates this local
        // envelope. Device membership signatures are intentionally not an
        // at-rest key dependency.
        return unwrapSegmentKey(this.storageKek, stable, { verify: async () => true })
      }
    }
    const current = await this.epochs.currentVaultEpoch(identityId)
    if (!current.selfGroupId) throw new TypeError('current vault self group is empty')
    const wrap = await this.wraps.readSegmentKeyWrap(identityId, segmentId, current.epoch)
    if (!wrap) throw new Error('current-epoch SegmentKeyWrap is unavailable; restore grant is required')
    if (wrap.identityId !== identityId || wrap.segmentId !== segmentId || wrap.selfGroupId !== current.selfGroupId || wrap.recipientEpoch !== current.epoch) {
      throw new TypeError('stored SegmentKeyWrap does not match current vault epoch')
    }
    const vek = await this.epochs.deriveVaultEpochKey(identityId, current.selfGroupId, current.epoch)
    try {
      return await unwrapSegmentKey(vek, wrap, this.signer)
    } finally {
      vek.fill(0)
    }
  }
}
