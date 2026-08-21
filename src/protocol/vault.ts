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

export type VaultEventKind =
  | 'message.add'
  | 'message.edit'
  | 'message.tombstone'
  | 'mailbox.set'
  | 'keyword.set'
  | 'thread.set'
  | 'reaction.set'
  | 'read.set'
  | 'settings.set'
  | 'transport.result'
  | 'contact-key.set'

export interface VaultEventV1 {
  version: 1
  id: VaultEventId
  identityId: IdentityId
  actorDeviceId: DeviceId
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
