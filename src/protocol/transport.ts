import type { IngressAckV1, IngressEnvelopeV1 } from './ingress.ts'
import type { DeviceId, IdentityId } from './ids.ts'

export interface RecipientReference {
  address?: string
  did?: string
}

export interface RecipientResolution {
  identityId: IdentityId
  deviceIds: DeviceId[]
}

export interface IngressOfferResult {
  accepted: boolean
  ingressId: string
  expiresAt: string
}

export interface TransportResult {
  identityId: IdentityId
  outboundEventId: string
  status: 'accepted' | 'temporary-failure' | 'permanent-failure'
  occurredAt: string
  detail?: string
}

export interface PushRequest {
  identityId: IdentityId
  deviceIds: DeviceId[]
  kind: 'ingress-available' | 'delivery-available' | 'restore-requested'
  opaqueNotificationId: string
}

/** The only host surface available to first-party transport adapters. */
export interface TransportAdapterHost {
  resolveRecipient(input: RecipientReference): Promise<RecipientResolution>
  offerIngress(input: IngressEnvelopeV1): Promise<IngressOfferResult>
  acknowledgeIngress(input: IngressAckV1): Promise<void>
  recordTransportResult(input: TransportResult): Promise<void>
  publishPush(input: PushRequest): Promise<void>
}

