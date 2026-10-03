import type { SegmentId, IdentityId } from '../../../protocol/ids.ts'

/** Local consumers resolve a SegmentKey by segment. */
export interface SegmentKeyResolver {
  resolveSegmentKey(identityId: IdentityId, segmentId: SegmentId): Promise<Uint8Array>
}

/** Reads a SegmentKey straight from this device's segment store: its own
 * segments and every sibling's, as Vault Sync delivered them. */
export class StoredSegmentKeyResolver implements SegmentKeyResolver {
  constructor(private readonly segments: { readSegmentKey(identityId: IdentityId, segmentId: SegmentId): Promise<Uint8Array | undefined> }) {}

  async resolveSegmentKey(identityId: IdentityId, segmentId: SegmentId): Promise<Uint8Array> {
    const key = await this.segments.readSegmentKey(identityId, segmentId)
    if (!key) throw new Error('this device does not hold the SegmentKey yet; it arrives with Vault Sync')
    return key
  }
}
