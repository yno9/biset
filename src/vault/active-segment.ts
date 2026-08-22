import type { IdentityId, SegmentId } from '../protocol/ids.ts'
import type { SegmentKeyWrapV1 } from '../protocol/vault.ts'

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
