import type { IdentityId, SegmentId } from '../../../protocol/ids.ts'
import type { ActiveVaultSegmentStore, VaultSegmentRecord } from './store.ts'

/** The segment this device writes new objects into. Its key stays local;
 * Vault Sync carries it to sibling devices along with those objects. */
export interface ActiveVaultSegment {
  segmentId: SegmentId
  segmentKey: Uint8Array
}

export function assertActiveVaultSegment(_identityId: IdentityId, segment: ActiveVaultSegment, purpose: string): void {
  if (!segment.segmentId || segment.segmentKey.length !== 32) throw new TypeError(`active vault segment is invalid for ${purpose}`)
}

export interface ActiveVaultSegmentManagerOptions {
  identityId: IdentityId
  segments: ActiveVaultSegmentStore
  now?: () => Date
}

/** Returns this device's writable segment, minting one (a new random
 * SegmentKey) the first time. */
export class ActiveVaultSegmentManager {
  constructor(private readonly options: ActiveVaultSegmentManagerOptions) {}

  async activeSegment(): Promise<ActiveVaultSegment> {
    const { identityId, segments } = this.options
    const stored = await segments.currentSegment(identityId)
    if (stored) return { segmentId: stored.segmentId, segmentKey: stored.segmentKey }
    const record: VaultSegmentRecord = {
      identityId,
      segmentId: crypto.randomUUID(),
      segmentKey: crypto.getRandomValues(new Uint8Array(32)),
      sealed: false,
      createdAt: (this.options.now ?? (() => new Date()))().toISOString(),
    }
    await segments.sealAndActivateSegment(record)
    return { segmentId: record.segmentId, segmentKey: record.segmentKey }
  }
}
