import type {
  DeviceId,
  IdentityId,
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
  segmentId: SegmentId
  sourceEpoch: number
  recipientEpoch: number
  wrappedSegmentKey: Uint8Array
  grantorDeviceId: DeviceId
  grantedAt: string
  signature: Uint8Array
}

