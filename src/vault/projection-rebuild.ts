// PLAN.md §3.2/§5.2's "full projection rebuild" -- the disaster-recovery
// (and, today, also identity-bootstrap) counterpart to
// `VaultDeliveryProjector.verifyAndProject`'s incremental one-pack-at-a-time
// update. Where that one folds a single delivered pack onto whatever
// projection snapshot is already stored, this recomputes the ENTIRE
// projection from every event/object this identity has ever committed --
// for a brand-new identity with no `vault_projection` row yet (nothing else
// seeds one), or to recover from a corrupted/lost projection without
// re-fetching anything over the network.
import type { LocalJmapProjectionV1 } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection } from '../local-jmap/reducer.ts'
import type { IdentityId } from '../shared/protocol/ids.ts'
import { decryptVaultMutationRecords } from './mutation-records.ts'
import type { VaultEventVerifier } from './events.ts'
import type { SegmentKeyWrapVerifier } from './crypto.ts'
import { StoredSegmentKeyResolver, type VaultEpochKeyResolver } from './segment-key-resolver.ts'
import type { SegmentKeyWrapReader, VaultRecordReader } from './store.ts'

export interface RebuildLocalJmapProjectionOptions {
  identityId: IdentityId
  records: VaultRecordReader
  wraps: SegmentKeyWrapReader
  epochs: VaultEpochKeyResolver
  verifier: VaultEventVerifier & SegmentKeyWrapVerifier
  storageKek?: Uint8Array
}

/**
 * Reads every SegmentKey through the ordinary CURRENT-epoch
 * `StoredSegmentKeyResolver`, exactly like any other vault read -- this is
 * only correct because `maintainSelfGroup`'s self-grant sweep
 * (identity/bootstrap.ts's `selfGrantSegmentRewraps`) keeps every one of
 * this identity's OWN segments carried forward to the self group's current
 * epoch. A segment that sweep never reached (a device that skipped a boot,
 * or this rebuild racing ahead of it) makes the whole rebuild fail closed
 * with the same "restore grant is required" error an ordinary read of that
 * one segment would raise -- not a partial projection missing just that
 * segment's messages.
 */
export async function rebuildLocalJmapProjection(opts: RebuildLocalJmapProjectionOptions): Promise<LocalJmapProjectionV1> {
  const { identityId } = opts
  const [events, objects] = await Promise.all([
    opts.records.readVaultEvents(identityId),
    opts.records.readVaultObjects(identityId),
  ])
  const resolver = new StoredSegmentKeyResolver(opts.wraps, opts.epochs, opts.verifier, opts.storageKek)
  const records = await decryptVaultMutationRecords(identityId, events, objects, resolver, opts.verifier)
  const snapshot = reduceLocalJmapProjection(identityId, { mailboxes: [], emails: [] }, records)
  return { version: 1, identityId, ...snapshot }
}
