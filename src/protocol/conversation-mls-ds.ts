import type { DeviceId } from './ids.ts'

/**
 * Signed control messages for the Conversation Group MLS Delivery Service
 * (`docs/protocols/mls-ds-1.0.md`, RFC 9750 §5), carried over DIDComm.
 * Parallels `mls-ds.ts` (the Self Group DS) field-for-field EXCEPT it drops
 * `identityId` entirely -- membership is `(groupId, senderKid)`, judged by
 * this DS's own opaque roster, never by a single-owner identity concept
 * (PLAN_biset-mls-ds.md §7, decided 2026-08-31). Self Group's `mls-ds.ts` is
 * unmodified by this file's existence -- this is a parallel module, not a
 * generalization of it.
 *
 * As with mls-ds.ts, every field the DS uses to decide anything is
 * authenticated; the DS itself never inspects the opaque
 * `commit`/`proposal`/`groupInfo`/`privateMessage` bytes.
 */

export type ConversationLogEntryKind = 'commit' | 'welcome' | 'proposal' | 'application'

/** One delivered object, as the DS holds it: opaque payload plus the
 * ordering it was given. `application` is the one kind Self Group's
 * MlsLogEntry doesn't have -- PLAN-mimi.md's finding that Self Group's DS
 * never carries application data (Vault sync uses a separate ordered log)
 * but a Conversation Group's does, since fanning that out IS the DS's job here. */
export interface ConversationLogEntry {
  seq: number
  kind: ConversationLogEntryKind
  payload: Uint8Array
  epoch: string
  at: string
}

export interface ConversationGroupInfoAnswer { groupInfo?: Uint8Array; pendingRemovals: string[] }

export interface ConversationGroupCreateV1 {
  version: 1
  groupId: string
  creatorKid: DeviceId
  roster: DeviceId[]
  createdAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationCommitSubmitV1 {
  version: 1
  groupId: string
  /** MLS credential kid (`did#fragment`) of the committing device. */
  senderKid: DeviceId
  /** The epoch this commit was made FROM. */
  epoch: string
  commit: Uint8Array
  /** The resulting roster, as the sender claims it -- DS bookkeeping only,
   * never cryptographically verified against `commit` (same disclaimer as
   * mls-ds.ts's own `roster` field). */
  roster: DeviceId[]
  welcome?: Uint8Array
  welcomeTo?: DeviceId[]
  groupInfo?: Uint8Array
  submittedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationExternalCommitSubmitV1 {
  version: 1
  groupId: string
  senderKid: DeviceId
  epoch: string
  commit: Uint8Array
  groupInfo: Uint8Array
  submittedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationGroupInfoPullV1 {
  version: 1
  groupId: string
  requesterKid: DeviceId
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationKeyPackagePublishV1 {
  version: 1
  kid: DeviceId
  packages: Uint8Array[]
  publishedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

/** Unlike Self Group's MlsKeyPackageTakeV1 (which always means "give me a
 * spare for MY OWN new device"), a Conversation Group take is always FOR
 * someone else -- `targetKid` names whose KeyPackage the requester wants,
 * since there's no "this identity's own devices" concept here
 * (mls-ds-1.0.md §4.6). */
export interface ConversationKeyPackageTakeV1 {
  version: 1
  requesterKid: DeviceId
  targetKid: DeviceId
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationSelfRemoveSubmitV1 {
  version: 1
  groupId: string
  senderKid: DeviceId
  epoch: string
  proposal: Uint8Array
  /** The device kid declaring its own removal -- MUST equal `senderKid`. */
  removedKid: DeviceId
  submittedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationPendingRemovalsClearV1 {
  version: 1
  groupId: string
  /** Must be the group's last accepted commit's sender -- the DS enforces this itself. */
  requesterKid: DeviceId
  clearedKids: DeviceId[]
  clearedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationDeliveriesPullV1 {
  version: 1
  groupId: string
  requesterKid: DeviceId
  afterSeq: number
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationKeyPackageDropV1 {
  version: 1
  kid: DeviceId
  droppedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationKeyPackageCountPullV1 {
  version: 1
  kid: DeviceId
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface ConversationGroupsForPullV1 {
  version: 1
  requesterKid: DeviceId
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

/** mls-ds-1.0.md §5.1: application message fan-out, the one operation
 * Self Group's DS has no equivalent of (PLAN-mimi.md's finding). */
export interface ConversationMessageSubmitV1 {
  version: 1
  groupId: string
  senderKid: DeviceId
  epoch: string
  privateMessage: Uint8Array
  submittedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}
