import type { SegmentId, IdentityId, MlsEpoch } from '../protocol/ids.ts'
import type { SegmentKeyWrapReader } from './store.ts'
import { unwrapSegmentKey, type SegmentKeyWrapSigner } from './crypto.ts'

export interface CurrentVaultEpoch {
  selfGroupId: string
  epoch: MlsEpoch
}

/** MLS adapter boundary. VEK output is transient and must not be persisted. */
export interface VaultEpochKeyResolver {
  currentVaultEpoch(identityId: IdentityId): Promise<CurrentVaultEpoch>
  deriveVaultEpochKey(identityId: IdentityId, selfGroupId: string, epoch: MlsEpoch): Promise<Uint8Array>
}

/**
 * Looks up only the wrap for the current self-group epoch, verifies the
 * grantor signature, and unwraps one SegmentKey in memory. Old epoch wraps
 * are not fallback keys: a new/current-epoch grant is required for restore.
 */
export class StoredSegmentKeyResolver {
  constructor(
    private readonly wraps: SegmentKeyWrapReader,
    private readonly epochs: VaultEpochKeyResolver,
    private readonly signer: SegmentKeyWrapSigner,
  ) {}

  async resolveSegmentKey(identityId: IdentityId, segmentId: SegmentId): Promise<Uint8Array> {
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
