// biset's own domain-move wrapper around migrate.ts's abstract core: carries
// routing.json to the new location (via migrateWebvhLocation's
// afterNewLocationWritten hook — the same whole-document string
// substitution the signed log itself gets), migrates this device's own MLS
// self-group credential (mls/self-group.ts's migrateSelfGroupCredential),
// re-keys this device's local IdentityRecord (record-store.ts's own
// keyPath), and re-keys/clears the other local IndexedDB databases that are
// ALSO keyed by this identity's did:webvh string.
//
// Four separate things had to be found and fixed here before a domain move
// could ship at all (2026-08-26, none had ever shipped before this):
//
//   1. mls/self-group.ts's own selfGroupIdentityKey — the self group's
//      NETWORK identity (the id sent to the DS) is SCID-keyed, not
//      DID-keyed, so the group itself survives a move untouched.
//   2. Every LOCAL store (vault/store.ts's 18 object stores, mls/store.ts's
//      own self-group row) is still keyed by the raw did:webvh string —
//      without re-keying them too, every already-synced device's local
//      vault would go dark the moment `identity.did` changed, even though
//      the underlying MLS group and vault content are both still
//      completely intact.
//   3. This device's own MLS leaf CREDENTIAL still names the OLD did
//      (`${did}#device-hex}`) even after (1) and (2) — and
//      mls/webvh-authentication-service.ts's validateCredential resolves a
//      credential against the CURRENT document, which after the move no
//      longer lists that old-prefixed id anywhere. Without
//      migrateSelfGroupCredential (mls/group.ts's updateOwnCredential,
//      committed via this device's own UpdatePath — see its own header for
//      why an external-commit resync and a bundled Update proposal were
//      both tried and abandoned first), this device would be permanently
//      locked out of its own group the moment the move landed.
//   4. Ordering trap on top of (3): the migration commit's own submission
//      still has to be SIGNED and VERIFIED under `oldDeviceKid` (core's DS
//      authorizes `submitCommit` by current roster membership, which is
//      still the OLD kid at this point — see migrateSelfGroupCredential's
//      own note). Running the migration strictly AFTER the did:webvh move
//      landed is therefore a deadlock: `oldDeviceKid` is already
//      unresolvable by then, so the DS-side signature check fails before
//      the commit that would replace it ever gets submitted.
//      migrateWebvhLocation's own afterNewLocationWritten hook exists for
//      exactly this shape of problem — it runs in the window where the NEW
//      location's document already resolves (so the new credential the
//      commit installs validates once anyone processes it) but the OLD
//      location hasn't been told about the move yet (so `oldDeviceKid`
//      still resolves too) — the only point where both are simultaneously
//      valid, which the migration commit's own submission needs.
//
// Deliberately narrower than src.bak's own moveWebvhIdentity: no multi-relay
// alias sync (loadStoredAccounts/aliasAccountOnRelay), no separate mediator
// re-registration (identity/bootstrap.ts's enableDidComm already
// re-publishes routing.json's own DIDComm pointer the next time it runs,
// same as any other identity — a move doesn't need a special case for
// this).
import { migrateWebvhLocation } from './migrate.ts'
import { fetchRouting, putRouting, type RoutingDoc } from '../../didcomm/webvh-routing.ts'
import { encodeMultikey } from './multikey.ts'
import { defaultFetch } from '../../net-fetch.ts'
import type { IdentityRecord, IdentityRecordStore } from '../record-store.ts'
import type { IndexedDbVaultStore } from '../../vault/store.ts'
import type { IndexedDbMlsSelfGroupStore } from '../../mls/store.ts'
import type { IndexedDbMlsKeyPackageStore } from '../../mls/keypackage-store.ts'
import { migrateSelfGroupCredential, type SelfGroupSigner } from '../../mls/self-group.ts'
import type { CoreMlsDeliveryTransport } from '../../mls/core-mls-delivery-transport.ts'

export interface MoveWebvhIdentityOptions {
  recordStore: IdentityRecordStore
  record: IdentityRecord
  vaultStore: IndexedDbVaultStore
  selfGroupStore: IndexedDbMlsSelfGroupStore
  keyPackageStore: IndexedDbMlsKeyPackageStore
  /** Required, and only used, when `record.deviceKid` is set (this device
   * has already joined a self group) — migrateSelfGroupCredential's own
   * commit submission. */
  mlsTransport?: CoreMlsDeliveryTransport
  /** Signs with this device's MLS leaf signature key — a DIFFERENT key from
   * `signingPrivateKey` below, which signs the did:webvh log/routing.json
   * instead. Same conditional requirement as `mlsTransport`. */
  mlsSign?: SelfGroupSigner
  newDomain: string
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  /** See migrate.ts's own note — required, and only valid, while
   * pre-rotation is active. */
  nextKeyHash?: string
  fetch?: typeof globalThis.fetch
}

/** Moves this identity's did:webvh document to a new domain (same SCID),
 * carries routing.json over, migrates this device's own self-group
 * credential, and re-keys every local record. Every local field that
 * embeds the old DID as a string prefix (`deviceKid`, `didCommKid`) is
 * rewritten the same way the document's own verificationMethod ids are —
 * otherwise a subsequent DIDComm send or revoke would target a kid string
 * that no longer resolves anywhere. */
export async function moveWebvhIdentity(opts: MoveWebvhIdentityOptions): Promise<IdentityRecord> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  const oldDid = opts.record.did
  const rewriteFor = (newDid: string) => (value: string): string => value.split(oldDid).join(newDid)

  const { newDid } = await migrateWebvhLocation({
    oldDid,
    newDomain: opts.newDomain,
    signingPrivateKey: opts.signingPrivateKey,
    signingPublicKey: opts.signingPublicKey,
    ...(opts.nextKeyHash ? { nextKeyHash: opts.nextKeyHash } : {}),
    fetch: fetchImpl,
    // Runs after the NEW location's did.jsonl exists but BEFORE the OLD
    // location is told about the move -- see this file's own header (point
    // 4) on why the self-group credential migration specifically needs
    // this window, not "after the move completes".
    afterNewLocationWritten: async newDid => {
      const rewrite = rewriteFor(newDid)
      if (opts.record.deviceKid) {
        if (!opts.mlsTransport || !opts.mlsSign) throw new Error('moveWebvhIdentity: this device has a self group (deviceKid is set) -- mlsTransport and mlsSign are required')
        const newDeviceKid = rewrite(opts.record.deviceKid)
        await migrateSelfGroupCredential(
          opts.selfGroupStore, opts.mlsTransport, oldDid, newDid, opts.record.deviceKid, newDeviceKid, opts.mlsSign,
        )
        await opts.selfGroupStore.delete(oldDid)
      }

      const current = await fetchRouting(oldDid, fetchImpl)
      if (!current) return // nothing published yet -- nothing to carry over
      const carried = JSON.parse(JSON.stringify(current).split(oldDid).join(newDid)) as RoutingDoc
      // The key that just proved updateKeys authority above is, by
      // construction, the new location's own updateKeys too -- routing-http.ts's
      // own authorization check reads the target domain's CURRENT
      // updateKeys, which by this point is already the new location's.
      await putRouting(newDid, carried, { updateKey: encodeMultikey(opts.signingPublicKey), privateKey: opts.signingPrivateKey }, fetchImpl)
    },
  })

  const rewrite = rewriteFor(newDid)
  const movedRecord: IdentityRecord = {
    ...opts.record,
    did: newDid,
    ...(opts.record.deviceKid ? { deviceKid: rewrite(opts.record.deviceKid) } : {}),
    ...(opts.record.didCommKid ? { didCommKid: rewrite(opts.record.didCommKid) } : {}),
  }
  await opts.recordStore.put(movedRecord)
  await opts.recordStore.delete(oldDid)

  await opts.vaultStore.rekeyIdentity(oldDid, newDid)
  // See this file's own header -- an already-minted KeyPackage's kid is
  // baked into its signed credential and cannot be carried over; the pool
  // just needs refilling under the new kid, which ensureKeyPackagePool
  // (identity/bootstrap.ts, called every boot) already does on its own.
  await opts.keyPackageStore.clear()

  return movedRecord
}
