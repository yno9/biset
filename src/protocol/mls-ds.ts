import type { DeviceId, IdentityId } from './ids.ts'

/**
 * Signed control messages for the MLS self-group Delivery Service
 * (`core/mediation/mls-delivery-store.ts`, RFC 9750 §5). Every field the DS
 * uses to decide anything is authenticated; the DS itself never inspects the
 * opaque `commit`/`proposal`/`groupInfo` bytes (PLANMLSARCH.md §4.2).
 */

export interface MlsGroupCreationV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  creatorKid: DeviceId
  roster: DeviceId[]
  createdAt: string
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
  signature: Uint8Array
}

export interface MlsGroupInfoPullV1 {
  version: 1
  groupId: string
  identityId: IdentityId
  requesterKid: DeviceId
  requestedAt: string
  signature: Uint8Array
}

export interface MlsKeyPackagePublishV1 {
  version: 1
  identityId: IdentityId
  kid: DeviceId
  packages: Uint8Array[]
  publishedAt: string
  signature: Uint8Array
}

export interface MlsKeyPackageTakeV1 {
  version: 1
  identityId: IdentityId
  /** The current member requesting key packages, so it can add a new device. */
  requesterKid: DeviceId
  requestedAt: string
  signature: Uint8Array
}
