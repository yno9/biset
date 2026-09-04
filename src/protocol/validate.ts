import type { AdapterIngressOfferV1, IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from './ingress.ts'
import type { MailSubmissionRequestV1 } from './mail-submission.ts'
import { assertDeliverySeq, assertOpaqueId } from './ids.ts'
import type {
  RestoreCancelV1,
  RestoreControlPullV1,
  RestoreOfferV1,
  RestoreRequestV1,
  VaultDeliveryAckV1,
  VaultDeliveryAppendV1,
  VaultDeliveryPullV1,
} from './vault.ts'

export class ProtocolValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ProtocolValidationError'
  }
}

type UnknownRecord = Record<string, unknown>

function record(value: unknown, name: string): UnknownRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProtocolValidationError(`${name} must be an object`)
  }
  return value as UnknownRecord
}

function text(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) throw new ProtocolValidationError(`${name} must be a non-empty string`)
}

/** Opaque IDs (identity/device/ingress/checkpoint/request) get the stricter
 * bound (`ids.ts`'s `assertOpaqueId`) rather than plain `text`: they end up
 * as storage keys, not just display strings. */
function opaqueId(value: unknown, name: string): asserts value is string {
  try {
    assertOpaqueId(value, name)
  } catch (error) {
    throw new ProtocolValidationError(error instanceof Error ? error.message : `${name} is invalid`)
  }
}

function bytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length === 0) {
    throw new ProtocolValidationError(`${name} must be a non-empty Uint8Array`)
  }
}

function time(value: unknown, name: string): asserts value is string {
  text(value, name)
  if (Number.isNaN(Date.parse(value))) throw new ProtocolValidationError(`${name} must be an ISO date string`)
}

function exactKeys(source: UnknownRecord, allowed: readonly string[], name: string): void {
  for (const key of Object.keys(source)) {
    if (!allowed.includes(key)) throw new ProtocolValidationError(`${name} has unknown field ${key}`)
  }
}

export function assertIngressEnvelope(value: unknown): asserts value is IngressEnvelopeV1 {
  const input = record(value, 'IngressEnvelopeV1')
  exactKeys(input, [
    'version', 'ingressId', 'protocol', 'recipientIdentityId', 'recipientDeviceSnapshot',
    'createdAt', 'expiresAt', 'transportMetadata', 'sourceEvidence', 'protectedPayload', 'protectedPayloadHash',
  ], 'IngressEnvelopeV1')
  if (input.version !== 1) throw new ProtocolValidationError('IngressEnvelopeV1.version must be 1')
  opaqueId(input.ingressId, 'ingressId')
  if (input.protocol !== 'didcomm' && input.protocol !== 'mail' && input.protocol !== 'activitypub') {
    throw new ProtocolValidationError('protocol is unsupported')
  }
  opaqueId(input.recipientIdentityId, 'recipientIdentityId')
  if (!Array.isArray(input.recipientDeviceSnapshot) || input.recipientDeviceSnapshot.length === 0) {
    throw new ProtocolValidationError('recipientDeviceSnapshot must be a non-empty array')
  }
  const recipients = new Set<string>()
  for (const deviceId of input.recipientDeviceSnapshot) {
    opaqueId(deviceId, 'recipientDeviceSnapshot entry')
    if (recipients.has(deviceId)) throw new ProtocolValidationError('recipientDeviceSnapshot has a duplicate device')
    recipients.add(deviceId)
  }
  time(input.createdAt, 'createdAt')
  time(input.expiresAt, 'expiresAt')
  if (Date.parse(input.expiresAt) <= Date.parse(input.createdAt)) {
    throw new ProtocolValidationError('expiresAt must be after createdAt')
  }
  const metadata = record(input.transportMetadata, 'transportMetadata')
  for (const [key, entry] of Object.entries(metadata)) {
    text(key, 'transportMetadata key')
    if (typeof entry !== 'string') throw new ProtocolValidationError('transportMetadata values must be strings')
  }
  bytes(input.sourceEvidence, 'sourceEvidence')
  bytes(input.protectedPayload, 'protectedPayload')
  bytes(input.protectedPayloadHash, 'protectedPayloadHash')
}

function assertAdapterIngressOffer(value: unknown): asserts value is AdapterIngressOfferV1 {
  const input = record(value, 'AdapterIngressOfferV1')
  exactKeys(input, [
    'version', 'ingressId', 'protocol', 'recipientIdentityId', 'createdAt', 'expiresAt',
    'transportMetadata', 'sourceEvidence', 'protectedPayload', 'protectedPayloadHash',
  ], 'AdapterIngressOfferV1')
  if (input.version !== 1) throw new ProtocolValidationError('AdapterIngressOfferV1.version must be 1')
  opaqueId(input.ingressId, 'ingressId')
  if (input.protocol !== 'didcomm' && input.protocol !== 'mail' && input.protocol !== 'activitypub') throw new ProtocolValidationError('protocol is unsupported')
  opaqueId(input.recipientIdentityId, 'recipientIdentityId')
  time(input.createdAt, 'createdAt')
  time(input.expiresAt, 'expiresAt')
  if (Date.parse(input.expiresAt) <= Date.parse(input.createdAt)) throw new ProtocolValidationError('expiresAt must be after createdAt')
  const metadata = record(input.transportMetadata, 'transportMetadata')
  for (const [key, entry] of Object.entries(metadata)) {
    text(key, 'transportMetadata key')
    if (typeof entry !== 'string') throw new ProtocolValidationError('transportMetadata values must be strings')
  }
  bytes(input.sourceEvidence, 'sourceEvidence')
  bytes(input.protectedPayload, 'protectedPayload')
  bytes(input.protectedPayloadHash, 'protectedPayloadHash')
}

export function assertMailSubmissionRequest(value: unknown): asserts value is MailSubmissionRequestV1 {
  const input = record(value, 'MailSubmissionRequestV1')
  exactKeys(input, [
    'version', 'identityId', 'deviceId', 'mailFrom', 'rcptTo', 'rawRfc5322', 'submittedAt', 'signature',
  ], 'MailSubmissionRequestV1')
  if (input.version !== 1) throw new ProtocolValidationError('MailSubmissionRequestV1.version must be 1')
  opaqueId(input.identityId, 'identityId')
  opaqueId(input.deviceId, 'deviceId')
  text(input.mailFrom, 'mailFrom')
  if (!Array.isArray(input.rcptTo) || input.rcptTo.length === 0) {
    throw new ProtocolValidationError('rcptTo must be a non-empty array')
  }
  for (const address of input.rcptTo) text(address, 'rcptTo entry')
  bytes(input.rawRfc5322, 'rawRfc5322')
  time(input.submittedAt, 'submittedAt')
  bytes(input.signature, 'signature')
}

export function assertIngressPull(value: unknown): asserts value is IngressPullV1 {
  const input = record(value, 'IngressPullV1')
  exactKeys(input, ['version', 'identityId', 'recipientDeviceId', 'requestedAt', 'signature'], 'IngressPullV1')
  if (input.version !== 1) throw new ProtocolValidationError('IngressPullV1.version must be 1')
  opaqueId(input.identityId, 'identityId')
  opaqueId(input.recipientDeviceId, 'recipientDeviceId')
  time(input.requestedAt, 'requestedAt')
  bytes(input.signature, 'signature')
}

export function assertIngressAck(value: unknown): asserts value is IngressAckV1 {
  const input = record(value, 'IngressAckV1')
  exactKeys(input, [
    'version', 'ingressId', 'protectedPayloadHash', 'recipientDeviceId',
    'vaultEventId', 'checkpointId', 'ackedAt', 'signature',
  ], 'IngressAckV1')
  if (input.version !== 1) throw new ProtocolValidationError('IngressAckV1.version must be 1')
  opaqueId(input.ingressId, 'ingressId')
  bytes(input.protectedPayloadHash, 'protectedPayloadHash')
  opaqueId(input.recipientDeviceId, 'recipientDeviceId')
  opaqueId(input.vaultEventId, 'vaultEventId')
  opaqueId(input.checkpointId, 'checkpointId')
  time(input.ackedAt, 'ackedAt')
  bytes(input.signature, 'signature')
}

export function assertVaultDeliveryAppend(value: unknown): asserts value is VaultDeliveryAppendV1 {
  const input = record(value, 'VaultDeliveryAppendV1')
  exactKeys(input, [
    'version', 'identityId', 'appendId', 'payload', 'payloadHash', 'senderDeviceId', 'sentAt', 'signature',
  ], 'VaultDeliveryAppendV1')
  if (input.version !== 1) throw new ProtocolValidationError('VaultDeliveryAppendV1.version must be 1')
  opaqueId(input.identityId, 'identityId')
  opaqueId(input.appendId, 'appendId')
  bytes(input.payload, 'payload')
  bytes(input.payloadHash, 'payloadHash')
  opaqueId(input.senderDeviceId, 'senderDeviceId')
  time(input.sentAt, 'sentAt')
  bytes(input.signature, 'signature')
}

export function assertVaultDeliveryAck(value: unknown): asserts value is VaultDeliveryAckV1 {
  const input = record(value, 'VaultDeliveryAckV1')
  exactKeys(input, [
    'version', 'identityId', 'seq', 'payloadHash', 'recipientDeviceId', 'checkpointId', 'ackedAt', 'signature',
  ], 'VaultDeliveryAckV1')
  if (input.version !== 1) throw new ProtocolValidationError('VaultDeliveryAckV1.version must be 1')
  opaqueId(input.identityId, 'identityId')
  try {
    assertDeliverySeq(input.seq)
  } catch {
    throw new ProtocolValidationError('seq must be an unsigned 64-bit decimal string')
  }
  bytes(input.payloadHash, 'payloadHash')
  opaqueId(input.recipientDeviceId, 'recipientDeviceId')
  opaqueId(input.checkpointId, 'checkpointId')
  time(input.ackedAt, 'ackedAt')
  bytes(input.signature, 'signature')
}

export function assertVaultDeliveryPull(value: unknown): asserts value is VaultDeliveryPullV1 {
  const input = record(value, 'VaultDeliveryPullV1')
  exactKeys(input, ['version', 'identityId', 'recipientDeviceId', 'after', 'requestedAt', 'signature'], 'VaultDeliveryPullV1')
  if (input.version !== 1) throw new ProtocolValidationError('VaultDeliveryPullV1.version must be 1')
  opaqueId(input.identityId, 'identityId')
  opaqueId(input.recipientDeviceId, 'recipientDeviceId')
  try {
    assertDeliverySeq(input.after)
  } catch {
    throw new ProtocolValidationError('after must be an unsigned 64-bit decimal string')
  }
  time(input.requestedAt, 'requestedAt')
  bytes(input.signature, 'signature')
}

export function assertRestoreRequest(value: unknown): asserts value is RestoreRequestV1 {
  const input = record(value, 'RestoreRequestV1')
  exactKeys(input, [
    'version', 'requestId', 'identityId', 'requesterDeviceId', 'reason', 'knownManifestRoot', 'requestedAt', 'expiresAt', 'signature',
  ], 'RestoreRequestV1')
  if (input.version !== 1) throw new ProtocolValidationError('RestoreRequestV1.version must be 1')
  opaqueId(input.requestId, 'requestId')
  opaqueId(input.identityId, 'identityId')
  opaqueId(input.requesterDeviceId, 'requesterDeviceId')
  if (!['ttl-expired', 'retention-quota', 'delivery-confirmed', 'new-device'].includes(String(input.reason))) {
    throw new ProtocolValidationError('RestoreRequestV1.reason is unsupported')
  }
  if (input.knownManifestRoot !== undefined) text(input.knownManifestRoot, 'knownManifestRoot')
  time(input.requestedAt, 'requestedAt')
  time(input.expiresAt, 'expiresAt')
  if (Date.parse(input.expiresAt) <= Date.parse(input.requestedAt)) {
    throw new ProtocolValidationError('RestoreRequestV1.expiresAt must be after requestedAt')
  }
  bytes(input.signature, 'signature')
}

export function assertRestoreOffer(value: unknown): asserts value is RestoreOfferV1 {
  const input = record(value, 'RestoreOfferV1')
  exactKeys(input, [
    'version', 'requestId', 'identityId', 'requesterDeviceId', 'responderDeviceId', 'manifestRoot', 'offeredAt', 'expiresAt', 'signature',
  ], 'RestoreOfferV1')
  if (input.version !== 1) throw new ProtocolValidationError('RestoreOfferV1.version must be 1')
  opaqueId(input.requestId, 'requestId')
  opaqueId(input.identityId, 'identityId')
  opaqueId(input.requesterDeviceId, 'requesterDeviceId')
  opaqueId(input.responderDeviceId, 'responderDeviceId')
  if (input.responderDeviceId === input.requesterDeviceId) throw new ProtocolValidationError('RestoreOfferV1 responder must be a peer')
  opaqueId(input.manifestRoot, 'manifestRoot')
  time(input.offeredAt, 'offeredAt')
  time(input.expiresAt, 'expiresAt')
  if (Date.parse(input.expiresAt) <= Date.parse(input.offeredAt)) {
    throw new ProtocolValidationError('RestoreOfferV1.expiresAt must be after offeredAt')
  }
  bytes(input.signature, 'signature')
}

export function assertRestoreCancel(value: unknown): asserts value is RestoreCancelV1 {
  const input = record(value, 'RestoreCancelV1')
  exactKeys(input, ['version', 'requestId', 'identityId', 'requesterDeviceId', 'cancelledAt', 'signature'], 'RestoreCancelV1')
  if (input.version !== 1) throw new ProtocolValidationError('RestoreCancelV1.version must be 1')
  opaqueId(input.requestId, 'requestId')
  opaqueId(input.identityId, 'identityId')
  opaqueId(input.requesterDeviceId, 'requesterDeviceId')
  time(input.cancelledAt, 'cancelledAt')
  bytes(input.signature, 'signature')
}

export function assertRestoreControlPull(value: unknown): asserts value is RestoreControlPullV1 {
  const input = record(value, 'RestoreControlPullV1')
  exactKeys(input, ['version', 'identityId', 'deviceId', 'kind', 'requestedAt', 'signature'], 'RestoreControlPullV1')
  if (input.version !== 1) throw new ProtocolValidationError('RestoreControlPullV1.version must be 1')
  opaqueId(input.identityId, 'identityId')
  opaqueId(input.deviceId, 'deviceId')
  if (input.kind !== 'requests' && input.kind !== 'offers') throw new ProtocolValidationError('RestoreControlPullV1.kind is unsupported')
  time(input.requestedAt, 'requestedAt')
  bytes(input.signature, 'signature')
}
