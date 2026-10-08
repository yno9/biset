import type {
  DeviceId,
  IdentityId,
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
  'contact.set',
  'credential.openpgp.set',
  'credential.relationship-seed.set',
  'didcomm.control',
] as const

export type VaultEventKind = typeof VAULT_EVENT_KINDS[number]

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
