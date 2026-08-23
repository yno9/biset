// The self-group bootstrap: making this device a member of its identity's
// MLS self group, over the DS narrow HTTP API (core-mls-delivery-transport.ts)
// and RFC 9750's own external-join mechanism (RFC 9420 §11).
//
// Ported at the state-machine level from src.bak/mls/self-group.ts, trimmed
// to the part Vault Core actually needs: self group membership as the
// roster/VEK boundary (PLANIMPLEMENTATION.md §4.1). Left out on purpose:
//
//   - Application-message device sync (syncToOwnDevices, DeviceSyncPayload,
//     receiveSelfGroupDelivery/catchUpSelfGroup). Vault Core's vault
//     delivery (PLAN.md §2.3) already serves that role; MLS application
//     messages are not a second delivery channel for the same content
//     (PLAN.md's still-open "should submitApplication be ported at all").
//     `reflectPendingSelfGroupCommits`, below, is NOT this — it pulls and
//     applies COMMITs only (never application messages), purely so an
//     existing member's own view of the group (and roster projection) stays
//     current; it carries no message content anywhere.
//   - DIDComm transport-key extension handling (memberTransportKeys) and
//     the stale-leaf recovery escape hatch (staleSelfGroupKids /
//     recoveryAuthenticationService) — both belong to the DIDComm-device-key
//     concept this rewrite does not carry forward as-is
//     (PLANMLSDIDCRED.md's open items).
//   - pendingRemovals follow-through (applyPendingRemovals) and add/remove
//     device operations (addDevicesToSelfGroup/removeDeviceFromSelfGroup) —
//     real self-group operations, but not needed for the bootstrap path and
//     each deserving its own scrutiny (KeyPackage fetch races, Welcome
//     fan-out) rather than a rushed port alongside this one.
//
// The caller supplies `sign`: an Ed25519 signature over this device's OWN
// MLS leaf signature key (KeyPackage.privatePackage.signaturePrivateKey),
// the same key core's Ed25519MlsDsSignatureVerifier resolves via DID
// (mls/webvh-authentication-service.ts's "no new key type" stance,
// PLANMLSDIDCRED.md §2.3).
import { sha256 } from '@noble/hashes/sha2.js'
import {
  confirmCommit,
  createMlsGroup,
  epochOf,
  groupInfoEpoch,
  groupInfoForExternalJoin,
  isActiveMember,
  joinGroupExternally,
  processIncoming,
  rekey,
  type OwnKeyPackage,
} from './group.ts'
import type { ClientState } from './vendor/index.ts'
import type { CoreMlsDeliveryTransport } from './core-mls-delivery-transport.ts'
import type { CoreRosterInstallTransport } from './core-roster-install-transport.ts'
import { buildAcceptedSelfGroupProjection, signRosterInstall } from './roster-projection.ts'
import type { MlsSelfGroupStateStore } from './store.ts'
import { mlsEpoch, type DeliverySeq } from '../protocol/ids.ts'
import {
  mlsCommitSubmissionSigningBytes,
  mlsDeliveriesPullSigningBytes,
  mlsExternalCommitSubmissionSigningBytes,
  mlsGroupCreationSigningBytes,
  mlsGroupInfoPullSigningBytes,
} from '../protocol/signing.ts'
import type { MlsCommitSubmissionV1, MlsDeliveriesPullV1, MlsExternalCommitSubmissionV1, MlsGroupCreationV1, MlsGroupInfoPullV1 } from '../protocol/mls-ds.ts'

/** Domain separator so this hash can never collide with any other use of an identity id as key material. */
const SELF_GROUP_LABEL = 'biset-self-group/1'

/** Signs with this device's MLS leaf signature key. Synchronous because the
 * key is already in memory (ed25519.sign is not async); returning a plain
 * value (not a Promise) is allowed since callers `await` it regardless. */
export type SelfGroupSigner = (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>

/** The self group's id, derived from the identity's own id.
 *
 * Deterministic on purpose: a freshly restored device knows nothing but its
 * seed and must be able to name the group it belongs to before it can ask
 * anyone anything. Random ids would need a lookup service to map identity to
 * group, which is one more thing to keep authoritative. */
export function selfGroupIdHex(identityId: string): string {
  const bytes = sha256(new TextEncoder().encode(`${SELF_GROUP_LABEL} ${identityId}`))
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

/** Create the self group. Done once per identity, by its first device. */
export async function createSelfGroup(
  transport: CoreMlsDeliveryTransport,
  identityId: string,
  deviceKid: string,
  kp: OwnKeyPackage,
  sign: SelfGroupSigner,
  now: () => Date = () => new Date(),
): Promise<ClientState> {
  const state = await createMlsGroup(sha256(new TextEncoder().encode(`${SELF_GROUP_LABEL} ${identityId}`)), kp)
  const creation: Omit<MlsGroupCreationV1, 'signature'> = {
    version: 1, groupId: selfGroupIdHex(identityId), identityId, creatorKid: deviceKid, roster: [], createdAt: now().toISOString(),
  }
  await transport.createGroup({ ...creation, signature: await sign(mlsGroupCreationSigningBytes(creation)) })
  // Publish a GroupInfo immediately: until one exists, a second device of
  // this identity cannot join at all, and the first device may not be
  // online again when that second device appears.
  return publishGroupInfo(transport, identityId, deviceKid, state, sign, now)
}

/** Advance the group by an empty commit whose only purpose is to leave a fresh GroupInfo with the DS. */
async function publishGroupInfo(
  transport: CoreMlsDeliveryTransport,
  identityId: string,
  deviceKid: string,
  state: ClientState,
  sign: SelfGroupSigner,
  now: () => Date,
): Promise<ClientState> {
  const result = await rekey(state)
  const submission: Omit<MlsCommitSubmissionV1, 'signature'> = {
    version: 1,
    groupId: selfGroupIdHex(identityId),
    identityId,
    senderKid: deviceKid,
    epoch: mlsEpoch(epochOf(state)),
    commit: result.commit,
    roster: [deviceKid],
    groupInfo: await groupInfoForExternalJoin(result.state),
    submittedAt: now().toISOString(),
  }
  const outcome = await transport.submitCommit({ ...submission, signature: await sign(mlsCommitSubmissionSigningBytes(submission)) })
  if (!outcome.ok) throw new Error(`publishGroupInfo: commit rejected (${outcome.reason})`)
  confirmCommit(result)
  return result.state
}

/**
 * Join this identity's self group as a NEW DEVICE, with no other device of
 * ours needing to be online — RFC 9420 §11's external commit against the
 * GroupInfo the DS holds.
 *
 * Returns undefined when the group cannot be joined yet: either no
 * GroupInfo has been published (the caller should fall back to
 * `createSelfGroup`), or this attempt lost an epoch race against another
 * commit (the caller should retry against the DS's now-current GroupInfo).
 * Both are ordinary, expected outcomes, not failures.
 */
export async function joinSelfGroupExternally(
  transport: CoreMlsDeliveryTransport,
  identityId: string,
  deviceKid: string,
  kp: OwnKeyPackage,
  sign: SelfGroupSigner,
  now: () => Date = () => new Date(),
): Promise<ClientState | undefined> {
  const groupId = selfGroupIdHex(identityId)
  const pull: Omit<MlsGroupInfoPullV1, 'signature'> = { version: 1, groupId, identityId, requesterKid: deviceKid, requestedAt: now().toISOString() }
  const { groupInfo } = await transport.pullGroupInfo({ ...pull, signature: await sign(mlsGroupInfoPullSigningBytes(pull)) })
  if (!groupInfo) return undefined

  const result = await joinGroupExternally(groupInfo, kp)
  const submission: Omit<MlsExternalCommitSubmissionV1, 'signature'> = {
    version: 1,
    groupId,
    identityId,
    senderKid: deviceKid,
    epoch: mlsEpoch(groupInfoEpoch(groupInfo)),
    commit: result.commit,
    groupInfo: await groupInfoForExternalJoin(result.state),
    submittedAt: now().toISOString(),
  }
  const outcome = await transport.submitExternalCommit({ ...submission, signature: await sign(mlsExternalCommitSubmissionSigningBytes(submission)) })
  if (!outcome.ok) {
    if (outcome.reason === 'epoch-conflict') return undefined
    throw new Error(`joinSelfGroupExternally: commit rejected (${outcome.reason})`)
  }
  confirmCommit(result)
  return result.state
}

/**
 * Make sure this device is IN its identity's self group: creating the group
 * if this is the first device, joining it externally otherwise. Idempotent
 * — a device that already holds active member state for this identity
 * returns it untouched.
 *
 * Does not retry an epoch-conflict from `joinSelfGroupExternally` (the
 * caller decides the backoff/retry policy) and does not attempt the
 * pre-rewrite implementation's stale-leaf recovery or pendingRemovals
 * follow-through — see this module's header for what's deliberately left
 * for a later, separately-reviewed change.
 */
export async function ensureSelfGroup(
  store: MlsSelfGroupStateStore,
  transport: CoreMlsDeliveryTransport,
  identityId: string,
  deviceKid: string,
  kp: OwnKeyPackage,
  sign: SelfGroupSigner,
  now: () => Date = () => new Date(),
): Promise<ClientState | undefined> {
  const stored = await store.load(identityId)
  if (stored && isActiveMember(stored.state, deviceKid)) return stored.state

  const state = (await joinSelfGroupExternally(transport, identityId, deviceKid, kp, sign, now))
    ?? (await createSelfGroup(transport, identityId, deviceKid, kp, sign, now))
  await store.save(identityId, selfGroupIdHex(identityId), state)
  return state
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
    { signingKeyIdForKid: kid => kid, deliveryFloorForNewDevice },
    now,
  )
  const install = await signRosterInstall(projection, deviceKid, sign, now)
  return rosterTransport.install(install)
}

/**
 * `ensureSelfGroup`, followed by `installCurrentRosterProjection` — skipped
 * entirely when `ensureSelfGroup` found this device already an active
 * member, since MLS state did not change and there is nothing new to
 * reflect. See `installCurrentRosterProjection` for why a `'rejected'`
 * outcome (the ordinary case for a device that just joined as a new,
 * not-yet-trusted member) is not treated as an error here.
 */
export async function ensureSelfGroupWithRosterInstall(
  store: MlsSelfGroupStateStore,
  mlsTransport: CoreMlsDeliveryTransport,
  rosterTransport: CoreRosterInstallTransport,
  identityId: string,
  deviceKid: string,
  kp: OwnKeyPackage,
  sign: SelfGroupSigner,
  deliveryFloorForNewDevice: () => Promise<DeliverySeq>,
  now: () => Date = () => new Date(),
): Promise<ClientState | undefined> {
  const alreadyActive = await store.load(identityId).then(stored => stored && isActiveMember(stored.state, deviceKid))
  const state = await ensureSelfGroup(store, mlsTransport, identityId, deviceKid, kp, sign, now)
  if (!state || alreadyActive) return state

  await installCurrentRosterProjection(rosterTransport, identityId, deviceKid, state, sign, deliveryFloorForNewDevice, now)
  return state
}

/**
 * Pulls every commit this device's stored self-group state hasn't applied
 * yet, applies each in epoch order, persists the result, and — if the
 * epoch actually advanced — calls `installCurrentRosterProjection` so a
 * device that just joined externally (which cannot install itself, per
 * `installCurrentRosterProjection`'s own doc comment) gets reflected by an
 * existing member instead. This is that "existing member notices and
 * reflects" half of the flow.
 *
 * Always pulls from `afterSeq: 0` and filters to entries whose `epoch`
 * matches this device's own current epoch before applying — the DS's log
 * for this group also holds entries this very device already produced
 * (e.g. its own genesis `publishGroupInfo` commit), and re-decrypting one
 * of those against an already-advanced key schedule fails. A cheaper
 * incremental cursor (tracking the last-seen `seq` per device) is possible
 * but not needed yet; the log is capped (`MAX_LOG_PER_GROUP`,
 * mls-delivery-store.ts) so re-fetching it whole stays bounded.
 *
 * Returns undefined when this device has no stored self-group state at all
 * (nothing to catch up) rather than throwing — that is `ensureSelfGroup`'s
 * job, not this one's.
 */
export async function reflectPendingSelfGroupCommits(
  store: MlsSelfGroupStateStore,
  mlsTransport: CoreMlsDeliveryTransport,
  rosterTransport: CoreRosterInstallTransport,
  identityId: string,
  deviceKid: string,
  sign: SelfGroupSigner,
  deliveryFloorForNewDevice: () => Promise<DeliverySeq>,
  now: () => Date = () => new Date(),
): Promise<ClientState | undefined> {
  const stored = await store.load(identityId)
  if (!stored) return undefined

  const groupId = selfGroupIdHex(identityId)
  const pull: Omit<MlsDeliveriesPullV1, 'signature'> = { version: 1, groupId, identityId, requesterKid: deviceKid, afterSeq: 0, requestedAt: now().toISOString() }
  const entries = await mlsTransport.pullDeliveries({ ...pull, signature: await sign(mlsDeliveriesPullSigningBytes(pull)) })

  const startEpoch = epochOf(stored.state)
  let state = stored.state
  for (const entry of entries) {
    if (entry.kind !== 'commit' || entry.epoch !== epochOf(state).toString()) continue
    state = (await processIncoming(state, entry.payload)).state
  }
  if (epochOf(state) === startEpoch) return state

  await store.save(identityId, groupId, state)
  // A 'rejected' outcome here means THIS device is also not yet trusted
  // under the roster's previous epoch (e.g. it only just external-joined
  // itself and hasn't been reflected by anyone else either) -- leave it for
  // whichever device the roster does trust to reflect next time it catches up.
  await installCurrentRosterProjection(rosterTransport, identityId, deviceKid, state, sign, deliveryFloorForNewDevice, now)
  return state
}
