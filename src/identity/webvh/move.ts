// biset's own domain-move wrapper around migrate.ts's abstract core: carries
// routing.json to the new location (via migrateWebvhLocation's
// afterNewLocationWritten hook — the same whole-document string
// substitution the signed log itself gets), re-keys this device's local
// IdentityRecord (record-store.ts's own keyPath), and re-keys the local stores
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
//   3. MLS device credentials deliberately remain unchanged. They are signed
//      by the stable Root Key and their old DID resolves through the webvh
//      move chain, so no MLS commit or KeyPackage invalidation is needed.
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

export interface MoveWebvhIdentityOptions {
  recordStore: IdentityRecordStore
  record: IdentityRecord
  vaultStore: IndexedDbVaultStore
  selfGroupStore: IndexedDbMlsSelfGroupStore
  newDomain: string
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  /** Fresh Spare commitment required by Biset's permanent pre-rotation. */
  nextKeyHash: string
  fetch?: typeof globalThis.fetch
}

/** Moves this identity's did:webvh document to a new domain (same SCID),
 * carries routing.json over and re-keys every DID-keyed local record. The
 * DIDComm kid is location-bound and rewritten; the Root-signed MLS device
 * kid remains stable. */
export async function moveWebvhIdentity(opts: MoveWebvhIdentityOptions): Promise<IdentityRecord> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  const oldDid = opts.record.did
  const rewriteFor = (newDid: string) => (value: string): string => value.split(oldDid).join(newDid)

  const { newDid, versionId } = await migrateWebvhLocation({
    oldDid,
    newDomain: opts.newDomain,
    signingPrivateKey: opts.signingPrivateKey,
    signingPublicKey: opts.signingPublicKey,
    nextKeyHash: opts.nextKeyHash,
    fetch: fetchImpl,
    // Runs after the new location exists so routing authorization can be
    // checked against its current update key.
    afterNewLocationWritten: async newDid => {
      const rewrite = rewriteFor(newDid)
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
    signPrivateKey: hex(opts.signingPrivateKey),
    signPublicKey: hex(opts.signingPublicKey),
    generation: versionId,
    // Root-signed MLS device credentials are immutable and remain valid
    // across a same-SCID move; their original DID resolves through the move
    // chain. Unlike DID document fragments, the device kid is not rewritten.
    ...(opts.record.didCommKid ? { didCommKid: rewrite(opts.record.didCommKid) } : {}),
  }
  await opts.recordStore.put(movedRecord)
  await opts.recordStore.delete(oldDid)

  await opts.vaultStore.rekeyIdentity(oldDid, newDid)
  const storedSelfGroup = await opts.selfGroupStore.load(oldDid)
  if (storedSelfGroup) {
    await opts.selfGroupStore.save(newDid, storedSelfGroup.selfGroupId, storedSelfGroup.state)
    await opts.selfGroupStore.delete(oldDid)
  }
  return movedRecord
}

function hex(value: Uint8Array): string { return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('') }
