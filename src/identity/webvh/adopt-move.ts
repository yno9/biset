// The passive counterpart to move.ts: a device that did NOT perform a
// domain move still needs to notice one happened (moved by a SIBLING
// device sharing this identity) and keep its own local bookkeeping
// (IdentityRecord, vault store, self-group row, KeyPackage pool) pointed at
// the identity's CURRENT location. Without this, every future
// add-device/revoke/routing-publish this device performs would still
// target the stale OLD location -- a permanent did:webvh log fork (the
// canonical, moved location never sees the write), and, worse, a
// revocation this device issues would never reach anyone resolving the
// identity's real, current document.
//
// Deliberately does NOT run mls/self-group.ts's migrateSelfGroupCredential:
// this device's own MLS leaf credential can safely keep naming its old
// did-prefix indefinitely. core/identity/webvh-signing-key-resolver.ts and
// mls/webvh-authentication-service.ts both match a kid by its `#fragment`
// against the resolved document's OWN current id, not the full kid
// verbatim, specifically so a device that never re-issues its own
// credential keeps validating through any number of a SIBLING's moves.
// Re-issuing it is a nice-to-have for long-term resilience against the
// ORIGINAL domain someday disappearing entirely, not something correctness
// here depends on.
//
// Converges one hop per call, even across back-to-back moves this device
// missed entirely, as long as each intermediate domain is still resolvable
// when this runs: migrateWebvhLocation's own dual-write only tells the
// IMMEDIATELY PRECEDING domain about any one move, so an identity moved
// twice while this device was offline needs two calls (e.g. two boots) to
// fully catch up. A domain decommissioned before a straggler device catches
// up through it is not handled here -- that is what the existing restore
// flow (a new-device join by another name) is for.
import { resolve } from './resolver.ts'
import type { IdentityRecord, IdentityRecordStore } from '../record-store.ts'
import type { IndexedDbVaultStore } from '../../vault/store.ts'
import type { IndexedDbMlsSelfGroupStore } from '../../mls/store.ts'
import type { IndexedDbMlsKeyPackageStore } from '../../mls/keypackage-store.ts'

export interface AdoptPendingMoveOptions {
  recordStore: IdentityRecordStore
  record: IdentityRecord
  vaultStore: IndexedDbVaultStore
  selfGroupStore: IndexedDbMlsSelfGroupStore
  keyPackageStore: IndexedDbMlsKeyPackageStore
}

/** Checks whether `record`'s identity has moved to a new domain since this
 * device last saw it and, if so, adopts the new location locally. Returns
 * the (possibly updated) record; on any resolution failure -- offline,
 * host unreachable -- returns `record` unchanged rather than throwing, since
 * this is routine upkeep (bootstrap.ts's `maintainSelfGroup`), not a user
 * action with something to report failure to. */
export async function adoptPendingMove(opts: AdoptPendingMoveOptions): Promise<IdentityRecord> {
  const oldDid = opts.record.did
  let doc
  try {
    doc = await resolve(oldDid)
  } catch {
    return opts.record
  }
  if (!doc || doc.id === oldDid) return opts.record

  const newDid = doc.id
  const rewrite = (value: string): string => value.split(oldDid).join(newDid)
  const movedRecord: IdentityRecord = {
    ...opts.record,
    did: newDid,
    ...(opts.record.deviceKid ? { deviceKid: rewrite(opts.record.deviceKid) } : {}),
    ...(opts.record.didCommKid ? { didCommKid: rewrite(opts.record.didCommKid) } : {}),
  }
  await opts.recordStore.put(movedRecord)
  await opts.recordStore.delete(oldDid)

  await opts.vaultStore.rekeyIdentity(oldDid, newDid)
  const stored = await opts.selfGroupStore.load(oldDid)
  if (stored) {
    await opts.selfGroupStore.save(newDid, stored.selfGroupId, stored.state)
    await opts.selfGroupStore.delete(oldDid)
  }
  // Same reasoning as move.ts's own tail: an already-minted KeyPackage's kid
  // is baked into its signed credential and cannot be carried over; the
  // pool just needs refilling under the (unchanged) device kid, which
  // ensureKeyPackagePool (identity/bootstrap.ts, called every boot) already
  // does on its own.
  await opts.keyPackageStore.clear()

  return movedRecord
}
