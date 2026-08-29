// The passive counterpart to move.ts: a device that did NOT perform a
// domain move still needs to notice one happened (moved by a SIBLING
// device sharing this identity) and keep its own local bookkeeping
// (IdentityRecord, vault store, self-group row) pointed at
// the identity's CURRENT location. Without this, every future
// add-device/revoke/routing-publish this device performs would still
// target the stale OLD location -- a permanent did:webvh log fork (the
// canonical, moved location never sees the write), and, worse, a
// revocation this device issues would never reach anyone resolving the
// identity's real, current document.
//
// MLS device credentials and KeyPackages remain unchanged: the credential
// is Root-signed and its original DID resolves through the move chain.
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

export interface AdoptPendingMoveOptions {
  recordStore: IdentityRecordStore
  record: IdentityRecord
  vaultStore: IndexedDbVaultStore
  selfGroupStore: IndexedDbMlsSelfGroupStore
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
    // MLS device ids are Root-authorized credentials and remain stable
    // across a same-SCID location move.
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
  return movedRecord
}
