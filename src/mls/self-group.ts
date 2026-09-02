// The self group's identity, and reflecting its current membership into
// core's roster projection -- the two pieces of this module BOTH the
// (retired) Coordinator DS path and the current biset-mimi path need, kept
// here as shared ground now that everything Coordinator-transport-specific
// (createSelfGroup, removeDeviceFromSelfGroup, rotateSelfGroupGeneration,
// joinSelfGroupExternally, ensureSelfGroup(WithRosterInstall),
// reflectPendingSelfGroupCommits) has been removed alongside Coordinator
// itself (PLAN_biset-mimi-server.md §19.h). `installCurrentRosterProjection`
// never depended on Coordinator's own transport -- it only ever needed
// core's `CoreRosterInstallTransport` and an already-current MLS
// `ClientState`, which `identity/bootstrap.ts`'s `ensureMimiCoreRoster`
// supplies from the biset-mimi Self/Vault room today.
import { sha256 } from '@noble/hashes/sha2.js'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import type { ClientState } from './vendor/index.ts'
import type { CoreRosterInstallTransport } from './core-roster-install-transport.ts'
import { buildAcceptedSelfGroupProjection, signRosterInstall } from './roster-projection.ts'
import type { DeliverySeq } from '../protocol/ids.ts'

/** Domain separator so this hash can never collide with any other use of an identity id as key material. */
const SELF_GROUP_LABEL = 'biset-self-group/1'

/** Signs with this device's MLS leaf signature key. Synchronous because the
 * key is already in memory (ed25519.sign is not async); returning a plain
 * value (not a Promise) is allowed since callers `await` it regardless. */
export type SelfGroupSigner = (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>

/** The stable part of an identity id to key the self group off of. A
 * did:webvh string embeds its domain (`did:webvh:{scid}:{domain}`), which a
 * domain move (identity/webvh/migrate.ts) changes on purpose while
 * preserving the SCID — did:webvh v1.0's own portability guarantee. Keying
 * the self group off the FULL did (as this used to) would silently orphan
 * every already-synced device and all vault content the moment a domain
 * moved, since the group id -- and therefore the MLS exporter-derived vault
 * epoch key chain -- would become a different, unrelated value. Keying off
 * the SCID instead makes a domain move free of any MLS/vault impact at all,
 * matching this project's own stated goal (domain portability should be
 * cheap and unconstrained, not a rare, heavy operation).
 *
 * Falls back to the raw identityId when it isn't a did:webvh string (a
 * generic MLS test fixture like `did:web:alice.example`) -- this file's own
 * self-group concept doesn't actually require did:webvh, only Vault Core's
 * real bootstrap path does. */
function selfGroupIdentityKey(identityId: string): string {
  try {
    return parseWebvhDid(identityId).scid
  } catch {
    return identityId
  }
}

/** The self group's id, derived from the identity's own (SCID-stable) key.
 *
 * Deterministic on purpose: a freshly restored device knows nothing but its
 * seed and must be able to name the group it belongs to before it can ask
 * anyone anything. Random ids would need a lookup service to map identity to
 * group, which is one more thing to keep authoritative. */
export function selfGroupIdHex(identityId: string): string {
  const bytes = sha256(new TextEncoder().encode(`${SELF_GROUP_LABEL} ${selfGroupIdentityKey(identityId)}`))
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Reflects `state`'s current self-group membership into core's roster, as
 * this device (`deviceKid`) is authorized to.
 *
 * `installRosterProjection`'s genesis-vs-post-genesis rule (authorizers.ts)
 * means only a device the roster ALREADY trusts under the previous epoch may
 * install the next one — except for a brand-new identity's genesis, whose
 * own projection vouches for its sole device. A device that just joined
 * externally is, by construction, not yet in the previous epoch's roster, so
 * its own install attempt is rejected; some existing member is expected to
 * call this again once it notices the new epoch (e.g. after processing that
 * member's commit). That is an ordinary outcome here, not an error — the
 * caller gets `'rejected'` back rather than a thrown exception so it does
 * not need to distinguish "I'm not yet trusted" from a real failure.
 *
 * `deliveryFloorForNewDevice` is threaded straight to
 * `buildAcceptedSelfGroupProjection` — see its own doc comment for why it
 * must be the CURRENT vault-delivery `latestSeq`.
 */
export async function installCurrentRosterProjection(
  rosterTransport: CoreRosterInstallTransport,
  identityId: string,
  deviceKid: string,
  state: ClientState,
  sign: SelfGroupSigner,
  deliveryFloorForNewDevice: () => Promise<DeliverySeq>,
  now: () => Date = () => new Date(),
): Promise<'installed' | 'already-current' | 'rejected'> {
  const previous = await rosterTransport.fetchProjection(identityId)
  const projection = await buildAcceptedSelfGroupProjection(
    identityId,
    selfGroupIdHex(identityId),
    identityId,
    state,
    previous,
    { deliveryFloorForNewDevice },
    now,
  )
  const install = await signRosterInstall(projection, deviceKid, sign, now)
  return rosterTransport.install(install)
}
