import type {
  CheckpointId,
  DeviceId,
  DeliverySeq,
  IdentityId,
  MlsEpoch,
  SegmentId,
  VaultEventId,
  VaultObjectId,
} from './ids.ts'

export const VAULT_EVENT_KINDS = [
  'message.add',
  'message.edit',
  'message.tombstone',
  'mailbox.set',
  'keyword.set',
  'thread.set',
  'reaction.set',
  'read.set',
  'settings.set',
  'transport.result',
  'contact-key.set',
  'credential.openpgp.set',
  'credential.didcomm.set',
  'didcomm.control',
  'didcomm.device-key.set',
] as const

export type VaultEventKind = typeof VAULT_EVENT_KINDS[number]

export interface VaultEventV1 {
  version: 1
  id: VaultEventId
  identityId: IdentityId
  actorDeviceId: DeviceId
  /** Root-authorized MLS device credential used to verify this historical
   * event after the actor is no longer a current Self Group member. Older
   * local/checkpoint records may omit it and are enriched during restore. */
  actorCredential?: Uint8Array
  actorSeq: number
  kind: VaultEventKind
  targetIds: string[]
  objectRefs: VaultObjectId[]
  parents: VaultEventId[]
  createdAt: string
  signature: Uint8Array
}

/** Immutable ciphertext. Payload plaintext is never stored by the core. */
export interface VaultObjectV1 {
  version: 1
  objectId: VaultObjectId
  segmentId: SegmentId
  nonce: Uint8Array
  ciphertext: Uint8Array
  ciphertextHash: Uint8Array
  plaintextLength: number
  aad: Uint8Array
}

/**
 * A payload is encrypted once under a random SegmentKey.  Existing peers may
 * create a new wrap for a newly-authorised current MLS epoch without changing
 * the ciphertext.
 */
export interface SegmentKeyWrapV1 {
  version: 1
  identityId: IdentityId
  selfGroupId: string
  segmentId: SegmentId
  sourceEpoch: MlsEpoch
  recipientEpoch: MlsEpoch
  nonce: Uint8Array
  aad: Uint8Array
  wrappedSegmentKey: Uint8Array
  grantorDeviceId: DeviceId
  grantedAt: string
  signature: Uint8Array
}

/** A device-visible immutable delivery body. The recipient snapshot is core-only metadata. */
export interface VaultDeliveryItemV1 {
  version: 1
  identityId: IdentityId
  seq: DeliverySeq
  payload: Uint8Array
  payloadHash: Uint8Array
  createdAt: string
  expiresAt: string
}

/** Sent only after the delivered payload is durably committed to the local vault. */
export interface VaultDeliveryAckV1 {
  version: 1
  identityId: IdentityId
  seq: DeliverySeq
  payloadHash: Uint8Array
  recipientDeviceId: DeviceId
  checkpointId: CheckpointId
  ackedAt: string
  signature: Uint8Array
}

export interface VaultDeliveryAppendV1 {
  version: 1
  identityId: IdentityId
  /** Client-generated idempotency key; normally the final vault event ID. */
  appendId: VaultEventId
  payload: Uint8Array
  payloadHash: Uint8Array
  senderDeviceId: DeviceId
  sentAt: string
  signature: Uint8Array
}

/** Signed request for the next bounded shared-vault delivery range. */
export interface VaultDeliveryPullV1 {
  version: 1
  identityId: IdentityId
  recipientDeviceId: DeviceId
  after: DeliverySeq
  requestedAt: string
  signature: Uint8Array
}

export type RestoreRequiredReason =
  | 'ttl-expired'
  | 'retention-quota'
  | 'delivery-confirmed'
  | 'new-device'

/** Small signed control only. It never embeds a manifest, object, or chunk. */
export interface RestoreRequestV1 {
  version: 1
  requestId: string
  identityId: IdentityId
  requesterDeviceId: DeviceId
  reason: RestoreRequiredReason
  knownManifestRoot?: string
  requestedAt: string
  expiresAt: string
  signature: Uint8Array
}

/** A peer is willing to perform a foreground manifest/chunk transfer. */
export interface RestoreOfferV1 {
  version: 1
  requestId: string
  identityId: IdentityId
  requesterDeviceId: DeviceId
  responderDeviceId: DeviceId
  manifestRoot: string
  offeredAt: string
  expiresAt: string
  signature: Uint8Array
}

export interface RestoreCancelV1 {
  version: 1
  requestId: string
  identityId: IdentityId
  requesterDeviceId: DeviceId
  cancelledAt: string
  signature: Uint8Array
}

/** Signed polling request for one side of the short-lived restore control plane. */
export interface RestoreControlPullV1 {
  version: 1
  identityId: IdentityId
  deviceId: DeviceId
  /** `requests` is for a peer offering help; `offers` is for the requester. */
  kind: 'requests' | 'offers'
  requestedAt: string
  signature: Uint8Array
}

/**
 * The entire content of an opaque wake-up push (PLAN.md §2.4). No body,
 * attachment name, or conversation metadata -- just enough for a peer
 * device to know it should poll `RestoreControlPullV1{kind:'requests'}`.
 * Deliberately unsigned: it carries no secret and no actionable claim by
 * itself (the peer's own signed pull is what actually authenticates
 * anything), and a forged/stale one costs the receiver nothing worse than
 * an unnecessary poll. A device that never receives one still reaches the
 * same state through ordinary polling -- this is a wake-up hint, not a
 * delivery channel.
 */
export interface RestoreNotifyV1 {
  version: 1
  identityId: IdentityId
  requestId: string
  requesterDeviceId: DeviceId
  /** A notification delivered after this time is worthless -- the request may already be gone -- and a receiver may discard it unopened. */
  notifyExpiresAt: string
}

export type DeliveryPullResult =
  | {
      kind: 'items'
      items: VaultDeliveryItemV1[]
      nextCursor: DeliverySeq
      retainedFrom: DeliverySeq
      latestSeq: DeliverySeq
    }
  | {
      kind: 'restoreRequired'
      requestedCursor: DeliverySeq
      retainedFrom: DeliverySeq
      latestSeq: DeliverySeq
      reason: RestoreRequiredReason
    }
