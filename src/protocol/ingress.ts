import type {
  CheckpointId,
  DeviceId,
  IdentityId,
  IngressId,
  VaultEventId,
} from './ids.ts'

export type IngressProtocol = 'didcomm' | 'mail' | 'activitypub'

/** A short-lived external payload; it is never a mailbox record. */
export interface IngressEnvelopeV1 {
  version: 1
  ingressId: IngressId
  protocol: IngressProtocol
  recipientIdentityId: IdentityId
  recipientDeviceSnapshot: DeviceId[]
  createdAt: string
  expiresAt: string
  transportMetadata: Record<string, string>
  sourceEvidence: Uint8Array
  protectedPayload: Uint8Array
  protectedPayloadHash: Uint8Array
}

/**
 * Input accepted from a first-party transport adapter. It intentionally has
 * no recipient-device snapshot: the core computes that from the accepted MLS
 * roster at the moment it accepts the ingress.
 */
export interface AdapterIngressOfferV1 {
  version: 1
  ingressId: IngressId
  protocol: IngressProtocol
  recipientIdentityId: IdentityId
  createdAt: string
  expiresAt: string
  transportMetadata: Record<string, string>
  sourceEvidence: Uint8Array
  protectedPayload: Uint8Array
  protectedPayloadHash: Uint8Array
}

/** A current self-group device's authenticated request for pending ingress. */
export interface IngressPullV1 {
  version: 1
  identityId: IdentityId
  recipientDeviceId: DeviceId
  requestedAt: string
  signature: Uint8Array
}

/** Sent only after the receiving device has durably committed its vault write. */
export interface IngressAckV1 {
  version: 1
  ingressId: IngressId
  protectedPayloadHash: Uint8Array
  recipientDeviceId: DeviceId
  vaultEventId: VaultEventId
  checkpointId: CheckpointId
  ackedAt: string
  signature: Uint8Array
}
