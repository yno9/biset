import { base64urlToBytes, bytesToBase64url } from './canonical.ts'
import type { DeliveryPullResult, RestoreRequiredReason, VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryItemV1, VaultDeliveryPullV1 } from './vault.ts'
import { assertVaultDeliveryAck, assertVaultDeliveryAppend, assertVaultDeliveryPull } from './validate.ts'

/** Strict JSON boundary for the bounded core HTTP API. */
export function encodeVaultDeliveryAppendWire(value: VaultDeliveryAppendV1): string {
  assertVaultDeliveryAppend(value)
  return JSON.stringify({ ...value, payload: bytesToBase64url(value.payload), payloadHash: bytesToBase64url(value.payloadHash), signature: bytesToBase64url(value.signature) })
}

export function decodeVaultDeliveryAppendWire(text: string): VaultDeliveryAppendV1 {
  const input = record(text)
  const value = { ...input, payload: binary(input.payload), payloadHash: binary(input.payloadHash), signature: binary(input.signature) }
  assertVaultDeliveryAppend(value)
  return value
}

export function encodeVaultDeliveryPullWire(value: VaultDeliveryPullV1): string {
  assertVaultDeliveryPull(value)
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeVaultDeliveryPullWire(text: string): VaultDeliveryPullV1 {
  const input = record(text)
  const value = { ...input, signature: binary(input.signature) }
  assertVaultDeliveryPull(value)
  return value
}

export function encodeVaultDeliveryAckWire(value: VaultDeliveryAckV1): string {
  assertVaultDeliveryAck(value)
  return JSON.stringify({ ...value, payloadHash: bytesToBase64url(value.payloadHash), signature: bytesToBase64url(value.signature) })
}

export function decodeVaultDeliveryAckWire(text: string): VaultDeliveryAckV1 {
  const input = record(text)
  const value = { ...input, payloadHash: binary(input.payloadHash), signature: binary(input.signature) }
  assertVaultDeliveryAck(value)
  return value
}

export function encodeDeliveryPullResultWire(value: DeliveryPullResult): string {
  if (value.kind === 'restoreRequired') return JSON.stringify(value)
  return JSON.stringify({ ...value, items: value.items.map(itemToWire) })
}

export function decodeDeliveryPullResultWire(text: string): DeliveryPullResult {
  const input = record(text)
  if (input.kind === 'restoreRequired') {
    if (typeof input.requestedCursor !== 'string' || typeof input.retainedFrom !== 'string' || typeof input.latestSeq !== 'string' || !['ttl-expired', 'retention-quota', 'delivery-confirmed', 'new-device'].includes(String(input.reason))) throw new TypeError('invalid vault delivery restore response')
    return { kind: 'restoreRequired', requestedCursor: input.requestedCursor, retainedFrom: input.retainedFrom, latestSeq: input.latestSeq, reason: input.reason as RestoreRequiredReason }
  }
  if (input.kind !== 'items' || !Array.isArray(input.items) || typeof input.nextCursor !== 'string' || typeof input.retainedFrom !== 'string' || typeof input.latestSeq !== 'string') throw new TypeError('invalid vault delivery pull response')
  return { kind: 'items', items: input.items.map(wireToItem), nextCursor: input.nextCursor, retainedFrom: input.retainedFrom, latestSeq: input.latestSeq }
}

function itemToWire(item: VaultDeliveryItemV1): Record<string, unknown> {
  return { ...item, payload: bytesToBase64url(item.payload), payloadHash: bytesToBase64url(item.payloadHash) }
}

function wireToItem(value: unknown): VaultDeliveryItemV1 {
  const item = value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined
  if (!item || item.version !== 1 || typeof item.identityId !== 'string' || typeof item.seq !== 'string' || typeof item.createdAt !== 'string' || typeof item.expiresAt !== 'string') throw new TypeError('invalid vault delivery item')
  return { version: 1, identityId: item.identityId, seq: item.seq, payload: binary(item.payload), payloadHash: binary(item.payloadHash), createdAt: item.createdAt, expiresAt: item.expiresAt }
}

function record(text: string): Record<string, unknown> {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('vault delivery HTTP body is not JSON') }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('vault delivery HTTP body must be an object')
  return value as Record<string, unknown>
}

function binary(value: unknown): Uint8Array {
  if (typeof value !== 'string') throw new TypeError('vault delivery HTTP binary field is invalid')
  return base64urlToBytes(value)
}
