import { base64urlToBytes, bytesToBase64url } from './canonical.ts'
import type { RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1 } from './vault.ts'
import { assertRestoreCancel, assertRestoreControlPull, assertRestoreOffer, assertRestoreRequest } from './validate.ts'

/** Strict JSON boundary for short restore controls; no vault content is serialised here. */
export function encodeRestoreRequestWire(value: RestoreRequestV1): string {
  assertRestoreRequest(value)
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeRestoreRequestWire(text: string): RestoreRequestV1 {
  const input = record(text)
  const value = { ...input, signature: binary(input.signature) }
  assertRestoreRequest(value)
  return value
}

export function encodeRestoreOfferWire(value: RestoreOfferV1): string {
  assertRestoreOffer(value)
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeRestoreOfferWire(text: string): RestoreOfferV1 {
  const input = record(text)
  const value = { ...input, signature: binary(input.signature) }
  assertRestoreOffer(value)
  return value
}

export function encodeRestoreCancelWire(value: RestoreCancelV1): string {
  assertRestoreCancel(value)
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeRestoreCancelWire(text: string): RestoreCancelV1 {
  const input = record(text)
  const value = { ...input, signature: binary(input.signature) }
  assertRestoreCancel(value)
  return value
}

export function encodeRestoreControlPullWire(value: RestoreControlPullV1): string {
  assertRestoreControlPull(value)
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeRestoreControlPullWire(text: string): RestoreControlPullV1 {
  const input = record(text)
  const value = { ...input, signature: binary(input.signature) }
  assertRestoreControlPull(value)
  return value
}

export function encodeRestoreRequestsWire(values: readonly RestoreRequestV1[]): string {
  return JSON.stringify(values.map(value => JSON.parse(encodeRestoreRequestWire(value))))
}

export function decodeRestoreRequestsWire(text: string): RestoreRequestV1[] {
  return array(text).map(value => {
    const input = recordValue(value)
    const decoded = { ...input, signature: binary(input.signature) }
    assertRestoreRequest(decoded)
    return decoded
  })
}

export function encodeRestoreOffersWire(values: readonly RestoreOfferV1[]): string {
  return JSON.stringify(values.map(value => JSON.parse(encodeRestoreOfferWire(value))))
}

export function decodeRestoreOffersWire(text: string): RestoreOfferV1[] {
  return array(text).map(value => {
    const input = recordValue(value)
    const decoded = { ...input, signature: binary(input.signature) }
    assertRestoreOffer(decoded)
    return decoded
  })
}

function record(text: string): Record<string, unknown> {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('restore control HTTP body is not JSON') }
  return recordValue(value)
}

function array(text: string): unknown[] {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('restore control HTTP body is not JSON') }
  if (!Array.isArray(value)) throw new TypeError('restore control HTTP body must be an array')
  return value
}

function recordValue(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('restore control HTTP body must be an object')
  return value as Record<string, unknown>
}

function binary(value: unknown): Uint8Array {
  if (typeof value !== 'string') throw new TypeError('restore control HTTP binary field is invalid')
  return base64urlToBytes(value)
}
