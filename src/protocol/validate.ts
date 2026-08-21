import type { IngressAckV1, IngressEnvelopeV1 } from './ingress.ts'
import { assertDeliverySeq } from './ids.ts'
import type { VaultDeliveryAckV1, VaultDeliveryAppendV1 } from './vault.ts'

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
  text(input.ingressId, 'ingressId')
  if (input.protocol !== 'didcomm' && input.protocol !== 'mail' && input.protocol !== 'activitypub') {
    throw new ProtocolValidationError('protocol is unsupported')
  }
  text(input.recipientIdentityId, 'recipientIdentityId')
  if (!Array.isArray(input.recipientDeviceSnapshot) || input.recipientDeviceSnapshot.length === 0) {
    throw new ProtocolValidationError('recipientDeviceSnapshot must be a non-empty array')
  }
  const recipients = new Set<string>()
  for (const deviceId of input.recipientDeviceSnapshot) {
    text(deviceId, 'recipientDeviceSnapshot entry')
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

export function assertIngressAck(value: unknown): asserts value is IngressAckV1 {
  const input = record(value, 'IngressAckV1')
  exactKeys(input, [
    'version', 'ingressId', 'protectedPayloadHash', 'recipientDeviceId',
    'vaultEventId', 'checkpointId', 'ackedAt', 'signature',
  ], 'IngressAckV1')
  if (input.version !== 1) throw new ProtocolValidationError('IngressAckV1.version must be 1')
  text(input.ingressId, 'ingressId')
  bytes(input.protectedPayloadHash, 'protectedPayloadHash')
  text(input.recipientDeviceId, 'recipientDeviceId')
  text(input.vaultEventId, 'vaultEventId')
  text(input.checkpointId, 'checkpointId')
  time(input.ackedAt, 'ackedAt')
  bytes(input.signature, 'signature')
}

export function assertVaultDeliveryAppend(value: unknown): asserts value is VaultDeliveryAppendV1 {
  const input = record(value, 'VaultDeliveryAppendV1')
  exactKeys(input, [
    'version', 'identityId', 'payload', 'payloadHash', 'recipientsAtAppend', 'createdAt', 'expiresAt',
  ], 'VaultDeliveryAppendV1')
  if (input.version !== 1) throw new ProtocolValidationError('VaultDeliveryAppendV1.version must be 1')
  text(input.identityId, 'identityId')
  bytes(input.payload, 'payload')
  bytes(input.payloadHash, 'payloadHash')
  if (!Array.isArray(input.recipientsAtAppend) || input.recipientsAtAppend.length === 0) {
    throw new ProtocolValidationError('recipientsAtAppend must be a non-empty array')
  }
  const recipients = new Set<string>()
  for (const deviceId of input.recipientsAtAppend) {
    text(deviceId, 'recipientsAtAppend entry')
    if (recipients.has(deviceId)) throw new ProtocolValidationError('recipientsAtAppend has a duplicate device')
    recipients.add(deviceId)
  }
  time(input.createdAt, 'createdAt')
  time(input.expiresAt, 'expiresAt')
  if (Date.parse(input.expiresAt) <= Date.parse(input.createdAt)) {
    throw new ProtocolValidationError('expiresAt must be after createdAt')
  }
}

export function assertVaultDeliveryAck(value: unknown): asserts value is VaultDeliveryAckV1 {
  const input = record(value, 'VaultDeliveryAckV1')
  exactKeys(input, [
    'version', 'identityId', 'seq', 'payloadHash', 'recipientDeviceId', 'checkpointId', 'ackedAt', 'signature',
  ], 'VaultDeliveryAckV1')
  if (input.version !== 1) throw new ProtocolValidationError('VaultDeliveryAckV1.version must be 1')
  text(input.identityId, 'identityId')
  try {
    assertDeliverySeq(input.seq)
  } catch {
    throw new ProtocolValidationError('seq must be an unsigned 64-bit decimal string')
  }
  bytes(input.payloadHash, 'payloadHash')
  text(input.recipientDeviceId, 'recipientDeviceId')
  text(input.checkpointId, 'checkpointId')
  time(input.ackedAt, 'ackedAt')
  bytes(input.signature, 'signature')
}
