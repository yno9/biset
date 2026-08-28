import { base64urlToBytes, bytesToBase64url } from './canonical.ts'
import { assertDeliverySeq, assertOpaqueId, assertVaultId, type DeliverySeq, type VaultId } from './ids.ts'

/**
 * Coordinator v2 is deliberately ignorant of devices and MLS.  The bearer
 * token identifies the Vault owner; every other field is opaque storage data.
 */
export interface VaultStreamV2 {
  version: 2
  vaultId: VaultId
  latestSeq: DeliverySeq
  checkpointSeq?: DeliverySeq
}

export interface VaultStreamAppendV2 {
  version: 2
  vaultId: VaultId
  appendId: string
  payload: Uint8Array
  payloadHash: Uint8Array
}

export interface VaultStreamItemV2 {
  version: 2
  vaultId: VaultId
  seq: DeliverySeq
  payload: Uint8Array
  payloadHash: Uint8Array
  createdAt: string
}

export interface VaultStreamPullV2 { version: 2; vaultId: VaultId; after: DeliverySeq }
export interface VaultStreamCheckpointPullV2 { version: 2; vaultId: VaultId }
export interface VaultStreamPullResultV2 { version: 2; items: VaultStreamItemV2[]; nextCursor: DeliverySeq; latestSeq: DeliverySeq }

export interface VaultStreamCheckpointPutV2 {
  version: 2
  vaultId: VaultId
  coveredSeq: DeliverySeq
  payload: Uint8Array
  payloadHash: Uint8Array
}

export interface VaultStreamCheckpointV2 {
  version: 2
  vaultId: VaultId
  coveredSeq: DeliverySeq
  payload: Uint8Array
  payloadHash: Uint8Array
  createdAt: string
}

export function decodeVaultStreamAppend(text: string): VaultStreamAppendV2 {
  const value = exact(text, ['version', 'vaultId', 'appendId', 'payload', 'payloadHash'])
  if (value.version !== 2) throw new TypeError('invalid Vault stream version')
  assertVaultId(value.vaultId)
  assertOpaqueId(value.appendId, 'appendId', 128)
  return { version: 2, vaultId: value.vaultId, appendId: value.appendId, payload: binary(value.payload), payloadHash: hash(value.payloadHash) }
}

export function decodeVaultStreamPull(text: string): VaultStreamPullV2 {
  const value = exact(text, ['version', 'vaultId', 'after'])
  if (value.version !== 2) throw new TypeError('invalid Vault stream version')
  assertVaultId(value.vaultId)
  assertDeliverySeq(value.after)
  return { version: 2, vaultId: value.vaultId, after: value.after }
}

export function decodeVaultStreamCheckpointPut(text: string): VaultStreamCheckpointPutV2 {
  const value = exact(text, ['version', 'vaultId', 'coveredSeq', 'payload', 'payloadHash'])
  if (value.version !== 2) throw new TypeError('invalid Vault stream checkpoint version')
  assertVaultId(value.vaultId)
  assertDeliverySeq(value.coveredSeq)
  return { version: 2, vaultId: value.vaultId, coveredSeq: value.coveredSeq, payload: binary(value.payload), payloadHash: hash(value.payloadHash) }
}

export function decodeVaultStreamCheckpointPull(text: string): VaultStreamCheckpointPullV2 {
  const value = exact(text, ['version', 'vaultId'])
  if (value.version !== 2) throw new TypeError('invalid Vault stream checkpoint pull version')
  assertVaultId(value.vaultId)
  return { version: 2, vaultId: value.vaultId }
}

export function encodeVaultStream(value: VaultStreamV2): string { return JSON.stringify(value) }
export function decodeVaultStream(text: string): VaultStreamV2 {
  const value = exact(text, Object.prototype.hasOwnProperty.call(JSON.parse(text), 'checkpointSeq') ? ['version', 'vaultId', 'latestSeq', 'checkpointSeq'] : ['version', 'vaultId', 'latestSeq'])
  if (value.version !== 2) throw new TypeError('invalid Vault stream response version')
  assertVaultId(value.vaultId)
  assertDeliverySeq(value.latestSeq)
  if (value.checkpointSeq !== undefined) assertDeliverySeq(value.checkpointSeq)
  return { version: 2, vaultId: value.vaultId, latestSeq: value.latestSeq, ...(value.checkpointSeq === undefined ? {} : { checkpointSeq: value.checkpointSeq }) }
}
export function encodeVaultStreamAppend(value: VaultStreamAppendV2): string {
  return JSON.stringify({ ...value, payload: bytesToBase64url(value.payload), payloadHash: bytesToBase64url(value.payloadHash) })
}
export function encodeVaultStreamPull(value: VaultStreamPullV2): string { return JSON.stringify(value) }
export function encodeVaultStreamPullResult(value: VaultStreamPullResultV2): string {
  return JSON.stringify({ ...value, items: value.items.map(item => ({ ...item, payload: bytesToBase64url(item.payload), payloadHash: bytesToBase64url(item.payloadHash) })) })
}
export function decodeVaultStreamPullResult(text: string): VaultStreamPullResultV2 {
  const value = exact(text, ['version', 'items', 'nextCursor', 'latestSeq'])
  if (value.version !== 2 || !Array.isArray(value.items)) throw new TypeError('invalid Vault stream pull response')
  assertDeliverySeq(value.nextCursor)
  assertDeliverySeq(value.latestSeq)
  const items = value.items.map(entry => {
    const item = exactValue(entry, ['version', 'vaultId', 'seq', 'payload', 'payloadHash', 'createdAt'])
    if (item.version !== 2) throw new TypeError('invalid Vault stream item version')
    assertVaultId(item.vaultId)
    assertDeliverySeq(item.seq)
    assertTimestamp(item.createdAt)
    return { version: 2 as const, vaultId: item.vaultId, seq: item.seq, payload: binary(item.payload), payloadHash: hash(item.payloadHash), createdAt: item.createdAt }
  })
  return { version: 2, items, nextCursor: value.nextCursor, latestSeq: value.latestSeq }
}
export function encodeVaultStreamCheckpointPut(value: VaultStreamCheckpointPutV2): string {
  return JSON.stringify({ ...value, payload: bytesToBase64url(value.payload), payloadHash: bytesToBase64url(value.payloadHash) })
}
export function encodeVaultStreamCheckpoint(value: VaultStreamCheckpointV2 | null): string {
  return JSON.stringify(value === null ? null : { ...value, payload: bytesToBase64url(value.payload), payloadHash: bytesToBase64url(value.payloadHash) })
}
export function decodeVaultStreamCheckpoint(text: string): VaultStreamCheckpointV2 | null {
  let parsed: unknown
  try { parsed = JSON.parse(text) } catch { throw new TypeError('Vault stream checkpoint response is not JSON') }
  if (parsed === null) return null
  const value = exactValue(parsed, ['version', 'vaultId', 'coveredSeq', 'payload', 'payloadHash', 'createdAt'])
  if (value.version !== 2) throw new TypeError('invalid Vault stream checkpoint response version')
  assertVaultId(value.vaultId)
  assertDeliverySeq(value.coveredSeq)
  assertTimestamp(value.createdAt)
  return { version: 2, vaultId: value.vaultId, coveredSeq: value.coveredSeq, payload: binary(value.payload), payloadHash: hash(value.payloadHash), createdAt: value.createdAt }
}

function exact(text: string, expected: string[]): Record<string, unknown> {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('Vault stream body is not JSON') }
  return exactValue(value, expected)
}

function exactValue(value: unknown, expected: string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Vault stream body must be an object')
  const record = value as Record<string, unknown>
  const actual = Object.keys(record).sort()
  const keys = [...expected].sort()
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) throw new TypeError('Vault stream body has unexpected fields')
  return record
}

function assertTimestamp(value: unknown): asserts value is string {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) throw new TypeError('Vault stream timestamp is invalid')
}

function binary(value: unknown): Uint8Array {
  if (typeof value !== 'string') throw new TypeError('Vault stream binary field must be base64url')
  return base64urlToBytes(value)
}

function hash(value: unknown): Uint8Array {
  const result = binary(value)
  if (result.length !== 32) throw new TypeError('payloadHash must contain 32 bytes')
  return result
}
