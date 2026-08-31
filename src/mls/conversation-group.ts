// Conversation Group orchestration: group.ts's group-agnostic RFC 9420
// engine (the SAME one self-group.ts uses) + mls-ds/client-transport.ts
// (the Conversation Group DS's HTTP transport), for the third-party group
// chat path PLAN_biset-mls-ds.md/PLAN-mimi.md describe. Mirrors
// self-group.ts's shape but is simpler in the ways that follow from having
// no single-owner identity:
//
//   - No identity-derived groupId (self-group.ts's selfGroupIdHex) -- a
//     Conversation Group has no stable "owner" to key one off, so groupId
//     is random (randomConversationGroupId) and knowing it IS the invitation
//     (mls-ds/store.ts's own groupInfoFor note, PLAN_biset-mls-ds.md §11-7).
//   - No roster-projection reflection (installCurrentRosterProjection) --
//     that machinery is Vault Coordinator's Self Group concept. A
//     Conversation Group's membership changes are reflected into Vault via
//     PLAN-mimi.md §4's DeltaChat-style control messages instead, a
//     different module's job (not this one's).
//   - The device credential (MlsDeviceCredentialV2, mls/device-credential.ts)
//     is the exact same one Self Group leaves use -- there is no separate
//     "Conversation Group credential" type. What differs is only which DS
//     verifies it (mls-ds/webvh-signing-key-resolver.ts, no identityId
//     cross-check) and which transport carries it.
//
// Application-message send/receive (sendConversationApplicationMessage,
// receiveConversationEntry) are the operations Self Group's own
// orchestration has no equivalent of (PLAN-mimi.md's finding) -- Self Group
// never routes application data through its DS.
import {
  addMembers,
  confirmCommit,
  createMlsGroup,
  encryptApplication,
  epochOf,
  groupInfoEpoch,
  groupInfoForExternalJoin,
  joinGroupExternally,
  memberList,
  processIncoming,
  rekey,
  removeMembers,
  type OwnKeyPackage,
} from './group.ts'
import type { ClientState, KeyPackage } from './vendor/index.ts'
import { bytesToHex, hexToBytes } from '../protocol/canonical.ts'
import { mlsEpoch } from '../protocol/ids.ts'
import {
  conversationCommitSubmitSigningBytes,
  conversationExternalCommitSubmitSigningBytes,
  conversationGroupCreateSigningBytes,
  conversationMessageSubmitSigningBytes,
} from '../protocol/conversation-mls-ds-signing.ts'
import type {
  ConversationCommitSubmitV1,
  ConversationExternalCommitSubmitV1,
  ConversationGroupCreateV1,
  ConversationMessageSubmitV1,
} from '../protocol/conversation-mls-ds.ts'
import type { ConversationMlsDeliveryTransport } from '../mls-ds/client-transport.ts'

export type ConversationGroupSigner = (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>

/** Random 32-byte hex groupId -- unlike Self Group, there is no stable
 * identity to derive a deterministic id from (multiple members, no single
 * owner). Knowing groupId IS the invitation. */
export function randomConversationGroupId(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)))
}

/** Creates a new Conversation Group. `groupId` should come from
 * `randomConversationGroupId` (or be supplied by an inviter for a group
 * this device is joining the creation flow of) -- this function does not
 * generate one itself, so a caller can log/share it before the group
 * actually exists on the DS. */
export async function createConversationGroup(
  transport: ConversationMlsDeliveryTransport,
  groupId: string,
  deviceKid: string,
  kp: OwnKeyPackage,
  sign: ConversationGroupSigner,
  now: () => Date = () => new Date(),
): Promise<ClientState> {
  const state = await createMlsGroup(hexToBytes(groupId), kp)
  const creation: Omit<ConversationGroupCreateV1, 'signature'> = { version: 1, groupId, creatorKid: deviceKid, roster: [], createdAt: now().toISOString() }
  await transport.createGroup({ ...creation, signature: await sign(conversationGroupCreateSigningBytes(creation)) })
  // Publish a GroupInfo immediately, same reason self-group.ts's
  // createSelfGroup does: until one exists, groupId alone -- this
  // Conversation Group's whole invitation (mls-ds/store.ts's own
  // groupInfoFor note) -- is useless, since nobody can join by external
  // commit without it.
  return publishConversationGroupInfo(transport, groupId, deviceKid, state, sign, now)
}

/** Advance the group by an empty commit whose only purpose is to leave a
 * fresh GroupInfo with the DS -- store.ts's submitCommit overwrites
 * `group.groupInfo` unconditionally on every commit, so any commit that
 * omits it (as `sendConversationApplicationMessage`'s submitMessage path
 * does not, but any future commit-shaped operation that forgot this would)
 * silently closes the external-join door again. */
async function publishConversationGroupInfo(
  transport: ConversationMlsDeliveryTransport,
  groupId: string,
  deviceKid: string,
  state: ClientState,
  sign: ConversationGroupSigner,
  now: () => Date,
): Promise<ClientState> {
  const result = await rekey(state)
  const submission: Omit<ConversationCommitSubmitV1, 'signature'> = {
    version: 1,
    groupId,
    senderKid: deviceKid,
    epoch: mlsEpoch(epochOf(state)),
    commit: result.commit,
    roster: memberList(result.state).map(m => m.kid),
    groupInfo: await groupInfoForExternalJoin(result.state),
    submittedAt: now().toISOString(),
  }
  const outcome = await transport.submitCommit({ ...submission, signature: await sign(conversationCommitSubmitSigningBytes(submission)) })
  if (!outcome.ok) throw new Error(`publishConversationGroupInfo: commit rejected (${outcome.reason})`)
  confirmCommit(result)
  return result.state
}

/** Join a Conversation Group as a NEW member via RFC 9420 §11 external
 * commit, against the GroupInfo the DS holds -- mirrors
 * self-group.ts's `joinSelfGroupExternally`, minus the identityId gate
 * (mls-ds/store.ts's groupInfoFor has none: knowing groupId already proved
 * this caller was invited). Returns undefined on the same two ordinary,
 * expected outcomes as the Self Group version: no GroupInfo published yet,
 * or an epoch race lost against a concurrent commit.
 *
 * `groupInfo` must be obtained out of band first (the caller already has
 * `groupId` from an invitation, and needs a group-info-pull against the DS
 * to get GroupInfo -- mls-ds/client-transport.ts's `pullGroupInfo`, not
 * duplicated here since this function only owns the MLS half). */
export async function joinConversationGroupExternally(
  transport: ConversationMlsDeliveryTransport,
  groupId: string,
  deviceKid: string,
  groupInfo: Uint8Array,
  kp: OwnKeyPackage,
  sign: ConversationGroupSigner,
  now: () => Date = () => new Date(),
): Promise<ClientState | undefined> {
  const result = await joinGroupExternally(groupInfo, kp)
  const submission: Omit<ConversationExternalCommitSubmitV1, 'signature'> = {
    version: 1,
    groupId,
    senderKid: deviceKid,
    epoch: mlsEpoch(groupInfoEpoch(groupInfo)),
    commit: result.commit,
    groupInfo: await groupInfoForExternalJoin(result.state),
    submittedAt: now().toISOString(),
  }
  const outcome = await transport.submitExternalCommit({ ...submission, signature: await sign(conversationExternalCommitSubmitSigningBytes(submission)) })
  if (!outcome.ok) {
    if (outcome.reason === 'epoch-conflict') return undefined
    throw new Error(`joinConversationGroupExternally: commit rejected (${outcome.reason})`)
  }
  confirmCommit(result)
  return result.state
}

/** Encrypts `plaintext` (a MimiContent CBOR encoding, mls/mimi-content.ts --
 * this function has no opinion on what's inside) as an MLS application
 * message and submits it to the DS, which fans it out as message-notify to
 * the rest of the group (mls-ds/fanout.ts) -- the one operation with no
 * Self Group equivalent (PLAN-mimi.md's finding: Self Group's DS never
 * carries application data). Returns the advanced ratchet state; the
 * caller is responsible for persisting it. */
export async function sendConversationApplicationMessage(
  state: ClientState,
  transport: ConversationMlsDeliveryTransport,
  groupId: string,
  deviceKid: string,
  plaintext: Uint8Array,
  sign: ConversationGroupSigner,
  now: () => Date = () => new Date(),
): Promise<ClientState> {
  const { state: nextState, wire } = await encryptApplication(state, plaintext)
  const submission: Omit<ConversationMessageSubmitV1, 'signature'> = {
    version: 1, groupId, senderKid: deviceKid, epoch: mlsEpoch(epochOf(state)), privateMessage: wire, submittedAt: now().toISOString(),
  }
  const outcome = await transport.submitMessage({ ...submission, signature: await sign(conversationMessageSubmitSigningBytes(submission)) })
  if (!outcome.ok) throw new Error(`sendConversationApplicationMessage: rejected (${outcome.reason})`)
  return nextState
}

/** Advances the group by a commit that adds `keyPackages` as new members
 * (an inviter's half of getting someone into the group -- taking their
 * KeyPackage via `transport.takeKeyPackage` first is the caller's job, same
 * split self-group.ts keeps between MLS state changes and DS I/O).
 * `newMemberKids` must line up 1:1 with `keyPackages` (the caller already
 * knows whose KeyPackage each one is, from the targetKid it took each one
 * under) -- mls-ds-1.0.md §4.2 requires `welcomeTo` whenever `welcome` is
 * present. */
export async function addMembersToConversationGroup(
  state: ClientState,
  transport: ConversationMlsDeliveryTransport,
  groupId: string,
  deviceKid: string,
  keyPackages: KeyPackage[],
  newMemberKids: string[],
  sign: ConversationGroupSigner,
  now: () => Date = () => new Date(),
): Promise<ClientState> {
  if (keyPackages.length !== newMemberKids.length) throw new TypeError('addMembersToConversationGroup: keyPackages and newMemberKids must line up 1:1')
  const result = await addMembers(state, keyPackages)
  const submission: Omit<ConversationCommitSubmitV1, 'signature'> = {
    version: 1,
    groupId,
    senderKid: deviceKid,
    epoch: mlsEpoch(epochOf(state)),
    commit: result.commit,
    // Every member across every distinct identity -- unlike Self Group's
    // memberKids(state, identityId) (one identity's own devices), a
    // Conversation Group's roster spans several identities, so this needs
    // memberList's full leaf-order membership, not a filter by one did.
    roster: memberList(result.state).map(m => m.kid),
    ...(result.welcome ? { welcome: result.welcome, welcomeTo: newMemberKids } : {}),
    groupInfo: await groupInfoForExternalJoin(result.state),
    submittedAt: now().toISOString(),
  }
  const outcome = await transport.submitCommit({ ...submission, signature: await sign(conversationCommitSubmitSigningBytes(submission)) })
  if (!outcome.ok) throw new Error(`addMembersToConversationGroup: commit rejected (${outcome.reason})`)
  confirmCommit(result)
  return result.state
}

/** Advances the group by a commit that removes `removedKids` -- unlike Self
 * Group's `removeDeviceFromSelfGroup` (which revokes another device of the
 * SAME identity as the committer), a Conversation Group has no notion of
 * "this identity's devices": `removedKids` may name devices of any member,
 * across any number of distinct identities, in one commit. RFC 9420
 * forbids a commit that removes its own committer (group.ts's own note on
 * `removeMembers`), so `removedKids` must not include `deviceKid` -- there
 * is no self-removal wrapper here yet, same as self-group.ts (its own
 * `leaveSelfGroup` referenced in group.ts's comments does not actually
 * exist either; `proposeSelfRemoval` + `transport.submitSelfRemove` are
 * available but unwrapped, for either group kind). */
export async function removeMembersFromConversationGroup(
  state: ClientState,
  transport: ConversationMlsDeliveryTransport,
  groupId: string,
  deviceKid: string,
  removedKids: string[],
  sign: ConversationGroupSigner,
  now: () => Date = () => new Date(),
): Promise<ClientState> {
  if (removedKids.includes(deviceKid)) throw new TypeError('removeMembersFromConversationGroup: cannot remove the committing device itself')
  const result = await removeMembers(state, removedKids)
  const submission: Omit<ConversationCommitSubmitV1, 'signature'> = {
    version: 1,
    groupId,
    senderKid: deviceKid,
    epoch: mlsEpoch(epochOf(state)),
    commit: result.commit,
    roster: memberList(result.state).map(m => m.kid),
    groupInfo: await groupInfoForExternalJoin(result.state),
    submittedAt: now().toISOString(),
  }
  const outcome = await transport.submitCommit({ ...submission, signature: await sign(conversationCommitSubmitSigningBytes(submission)) })
  if (!outcome.ok) throw new Error(`removeMembersFromConversationGroup: commit rejected (${outcome.reason})`)
  confirmCommit(result)
  return result.state
}

export interface ConversationIncomingEntry {
  state: ClientState
  /** Set only when the entry was an application message -- a commit/
   * proposal advances `state` with no plaintext to hand back. */
  plaintext?: Uint8Array
  /** The kid MLS itself authenticated as the sender -- set alongside
   * `plaintext` whenever `processIncoming` could resolve the sending leaf's
   * credential (group.ts's `memberAt`). A Vault projection MUST attribute a
   * message to this, never to anything self-reported inside the plaintext
   * (group.ts's own `processIncoming` doc comment on why). */
  sender?: string
}

/** Applies one deliveries-pull/message-notify entry -- a commit/proposal
 * advances group state with no plaintext; an application message decrypts
 * to `plaintext` (a MimiContent CBOR encoding, mls/mimi-content.ts's job to
 * decode, not this function's). */
export async function receiveConversationEntry(state: ClientState, payload: Uint8Array): Promise<ConversationIncomingEntry> {
  const result = await processIncoming(state, payload)
  return result.kind === 'message' ? { state: result.state, plaintext: result.message, ...(result.sender ? { sender: result.sender.kid } : {}) } : { state: result.state }
}
