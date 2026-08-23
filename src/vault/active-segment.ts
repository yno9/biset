import type { IdentityId, SegmentId } from '../protocol/ids.ts'
import type { SegmentKeyWrapV1 } from '../protocol/vault.ts'
import { createSegmentKeyWrap, type SegmentKeyWrapSigner } from './crypto.ts'
import type { VaultEpochKeyResolver } from './segment-key-resolver.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from './store.ts'

/**
 * The endpoint's current writable vault segment.  The SegmentKey remains
 * local; the supplied current-epoch wraps are the only form sent to sibling
 * devices in a shared delivery pack.
 */
export interface ActiveVaultSegment {
  segmentId: SegmentId
  segmentKey: Uint8Array
  keyWraps: SegmentKeyWrapV1[]
}

export function assertActiveVaultSegment(identityId: IdentityId, segment: ActiveVaultSegment, purpose: string): void {
  if (!segment.segmentId || segment.segmentKey.length !== 32 || segment.keyWraps.length === 0
    || segment.keyWraps.some(wrap => wrap.identityId !== identityId || wrap.segmentId !== segment.segmentId)) {
    throw new TypeError(`active vault segment does not match ${purpose} identity`)
  }
}

export interface ActiveVaultSegmentManagerOptions {
  identityId: IdentityId
  segments: ActiveVaultSegmentStore
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter
  epochs: VaultEpochKeyResolver
  signer: SegmentKeyWrapSigner
  now?: () => Date
}

/**
 * Produces the `ActiveVaultSegment` `vault-mutation-sink.ts`'s
 * `activeSegment()` option needs, minting a fresh segment (a new random
 * SegmentKey, a new current-epoch wrap) whenever the self-group epoch has
 * moved past whatever segment is currently active. This IS PLAN.md §4.2's
 * "seal the active segment after an MLS commit": `ActiveVaultSegmentStore.
 * sealAndActivateSegment` marks the old segment sealed in the same write
 * that activates the new one, so no caller can ever be handed a stale
 * (already-superseded) segment to encrypt a new object under — a device
 * the self group has since removed therefore never receives a wrap for
 * anything encrypted from this point on, since it has no current epoch left
 * to request one against.
 */
export class ActiveVaultSegmentManager {
  constructor(private readonly options: ActiveVaultSegmentManagerOptions) {}

  async activeSegment(): Promise<ActiveVaultSegment> {
    const { identityId, segments, wraps, epochs } = this.options
    const current = await epochs.currentVaultEpoch(identityId)
    const stored = await segments.currentSegment(identityId)

    if (stored && stored.selfGroupId === current.selfGroupId && stored.epoch === current.epoch) {
      const wrap = await wraps.readSegmentKeyWrap(identityId, stored.segmentId, current.epoch)
      if (wrap) return { segmentId: stored.segmentId, segmentKey: stored.segmentKey, keyWraps: [wrap] }
      // The segment record exists but its wrap does not -- a crash between
      // sealAndActivateSegment and writeSegmentKeyWrap on a prior call. The
      // SegmentKey itself was never handed out without a wrap alongside it
      // (this method is the only place either gets created), so it is safe
      // to mint the missing wrap for the SAME segment rather than a new one.
      const wrap2 = await this.mintWrap(stored)
      await wraps.writeSegmentKeyWrap(wrap2)
      return { segmentId: stored.segmentId, segmentKey: stored.segmentKey, keyWraps: [wrap2] }
    }

    const now = this.options.now ?? (() => new Date())
    const record: VaultSegmentRecord = {
      identityId,
      segmentId: crypto.randomUUID(),
      segmentKey: crypto.getRandomValues(new Uint8Array(32)),
      selfGroupId: current.selfGroupId,
      epoch: current.epoch,
      sealed: false,
      createdAt: now().toISOString(),
    }
    const wrap = await this.mintWrap(record)
    await segments.sealAndActivateSegment(record)
    await wraps.writeSegmentKeyWrap(wrap)
    return { segmentId: record.segmentId, segmentKey: record.segmentKey, keyWraps: [wrap] }
  }

  private async mintWrap(record: VaultSegmentRecord): Promise<SegmentKeyWrapV1> {
    const { identityId, epochs, signer } = this.options
    const now = this.options.now ?? (() => new Date())
    const vek = await epochs.deriveVaultEpochKey(identityId, record.selfGroupId, record.epoch)
    try {
      return await createSegmentKeyWrap(vek, record.segmentKey, {
        identityId,
        selfGroupId: record.selfGroupId,
        segmentId: record.segmentId,
        sourceEpoch: record.epoch,
        recipientEpoch: record.epoch,
        grantorDeviceId: signer.deviceId,
        grantedAt: now().toISOString(),
      }, signer)
    } finally {
      vek.fill(0)
    }
  }
}
