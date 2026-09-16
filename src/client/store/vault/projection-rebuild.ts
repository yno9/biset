// The full local-JMAP-projection rebuild: recomputes the ENTIRE projection
// from every event/object this identity has ever committed, rather than
// folding one new pack onto whatever is already stored
// (VaultDeliveryProjector's own incremental path). Two callers need this:
// seeding a brand-new identity's very first (empty) `vault_projection` row
// (nothing else does), and re-deriving the projection after Vault Sync
// merges another device's events/objects into this device's Vault --
// merging the CRDT log and object store does not, by itself, touch the
// separately-stored JMAP projection the inbox actually renders from, so
// without this a synced message is durable but invisible until whatever
// eventually calls this (found live, 2026-09-15: one Wallet device's own
// sent message never appeared on a sibling, since nothing there rebuilt
// the sibling's projection after the sync landed).
//
// A prior version of this file existed before the MIMI/MLS removal, wired
// to the old MLS self-group's own epoch resolver/verifier
// (MlsVaultEpochKeyResolver/MlsMembershipSegmentKeyWrapVerifier). It was
// deleted along with that system without a replacement for the
// Wallet-authorized boundary bootstrap.ts now uses instead -- this is that
// replacement, and it needs neither MLS type: `decryptVaultMutationRecords`
// only ever needed a `SegmentKeyResolver` and a `VaultEventVerifier`, both
// of which `buildWalletVaultCryptoBoundary`'s own `resolver`/`signer` already
// satisfy directly.
import type { LocalJmapProjectionV1 } from '../projection/gateway.ts'
import { reduceLocalJmapProjection } from '../projection/reducer.ts'
import type { IdentityId } from '../../../protocol/ids.ts'
import { decryptVaultMutationRecords } from './mutation-records.ts'
import type { VaultEventVerifier } from './events.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultRecordReader } from './store.ts'

export interface RebuildLocalJmapProjectionOptions {
  identityId: IdentityId
  records: VaultRecordReader
  resolver: SegmentKeyResolver
  verifier: VaultEventVerifier
}

export async function rebuildLocalJmapProjection(opts: RebuildLocalJmapProjectionOptions): Promise<LocalJmapProjectionV1> {
  const { identityId } = opts
  const [events, objects] = await Promise.all([
    opts.records.readVaultEvents(identityId),
    opts.records.readVaultObjects(identityId),
  ])
  const records = await decryptVaultMutationRecords(identityId, events, objects, opts.resolver, opts.verifier)
  const snapshot = reduceLocalJmapProjection(identityId, { mailboxes: [], emails: [] }, records)
  return { version: 1, identityId, ...snapshot }
}
