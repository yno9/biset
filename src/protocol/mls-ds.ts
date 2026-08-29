import type { DeviceId, IdentityId } from './ids.ts'

/**
 * Signed control messages for the MLS self-group Delivery Service
 * (`coordinator/mls-delivery-store.ts`, RFC 9750 §5). Every field the DS
 * uses to decide anything is authenticated; the DS itself never inspects the
 * opaque `commit`/`proposal`/`groupInfo` bytes (PLANMLSARCH.md §4.2).
 */

/** One delivered object, as the DS holds it: opaque payload plus the ordering it was given. */
export interface MlsLogEntry {
  seq: number
  kind: 'commit' | 'welcome' | 'proposal'
  payload: Uint8Array
  epoch: string
  at: string
}

export interface MlsGroupInfoAnswer { groupInfo?: Uint8Array; pendingRemovals: string[] }

export interface MlsGroupCreationV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  creatorKid: DeviceId
  roster: DeviceId[]
  createdAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsCommitSubmissionV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  /** MLS credential kid (`did#fragment`) of the committing device. */
  senderKid: DeviceId
  /** The epoch this commit was made FROM. */
  epoch: string
  commit: Uint8Array
  /** The resulting roster, as the sender claims it — DS bookkeeping only, never verified (PLANMLSARCH.md §4.2). */
  roster: DeviceId[]
  welcome?: Uint8Array
  welcomeTo?: DeviceId[]
  groupInfo?: Uint8Array
  submittedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsExternalCommitSubmissionV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  senderKid: DeviceId
  epoch: string
  commit: Uint8Array
  groupInfo?: Uint8Array
  submittedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsGroupInfoPullV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  requesterKid: DeviceId
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsKeyPackagePublishV1 {
  version: 1
  identityId: IdentityId
  kid: DeviceId
  packages: Uint8Array[]
  publishedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsKeyPackageTakeV1 {
  version: 1
  identityId: IdentityId
  /** The current member requesting key packages, so it can add a new device. */
  requesterKid: DeviceId
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsSelfRemoveSubmissionV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  senderKid: DeviceId
  epoch: string
  proposal: Uint8Array
  /** The device kid declaring its own removal — normally `senderKid` itself. */
  removedKid: DeviceId
  submittedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsPendingRemovalsClearV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  /** Must be the group's last accepted commit's sender — the DS enforces this itself. */
  requesterKid: DeviceId
  clearedKids: DeviceId[]
  clearedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsDeliveriesPullV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  requesterKid: DeviceId
  afterSeq: number
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsKeyPackageDropV1 {
  version: 1
  identityId: IdentityId
  kid: DeviceId
  droppedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsKeyPackageCountPullV1 {
  version: 1
  identityId: IdentityId
  kid: DeviceId
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}

export interface MlsGroupsForPullV1 {
  version: 1
  identityId: IdentityId
  requesterKid: DeviceId
  requestedAt: string
  deviceCredential?: Uint8Array
  signature: Uint8Array
}
