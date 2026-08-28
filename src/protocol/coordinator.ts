import { base64urlToBytes, bytesToBase64url, canonicalBytes } from './canonical.ts'
import {
  assertDeliverySeq,
  assertMlsEpoch,
  assertOpaqueId,
  assertVaultId,
  assertVaultMemberId,
  type DeliverySeq,
  type MlsEpoch,
  type VaultId,
  type VaultMemberId,
} from './ids.ts'

export interface VaultCoordinatorAppendV1 {
  version: 1
  vaultId: VaultId
  appendId: string
  senderMemberId: VaultMemberId
  groupEpoch: MlsEpoch
  payload: Uint8Array
  payloadHash: Uint8Array
  sentAt: string
  signature: Uint8Array
}

export interface VaultCoordinatorPullV1 {
  version: 1
  vaultId: VaultId
  recipientMemberId: VaultMemberId
  after: DeliverySeq
  requestedAt: string
  signature: Uint8Array
}

export interface VaultCoordinatorAckV1 {
  version: 1
  vaultId: VaultId
  recipientMemberId: VaultMemberId
  seq: DeliverySeq
  payloadHash: Uint8Array
  ackedAt: string
  signature: Uint8Array
}

/** Latest complete encrypted Vault checkpoint. Its plaintext format and keys
 * are endpoint-only; Coordinator sees only an opaque, content-hashed blob. */
export interface VaultCoordinatorCheckpointPutV1 {
  version: 1
  vaultId: VaultId
  writerMemberId: VaultMemberId
  coveredSeq: DeliverySeq
  payload: Uint8Array
  payloadHash: Uint8Array
  createdAt: string
  signature: Uint8Array
}

export interface VaultCoordinatorCheckpointPullV1 {
  version: 1
  vaultId: VaultId
}

export interface VaultCoordinatorCheckpointV1 {
  version: 1
  vaultId: VaultId
  writerMemberId: VaultMemberId
  coveredSeq: DeliverySeq
  payload: Uint8Array
  payloadHash: Uint8Array
  createdAt: string
}

export interface VaultCoordinatorOwnedVaultV1 {
  vaultId: VaultId
  latestSeq: DeliverySeq
  checkpointSeq?: DeliverySeq
}

export interface VaultCoordinatorItemV1 {
  version: 1
  vaultId: VaultId
  seq: DeliverySeq
  groupEpoch: MlsEpoch
  payload: Uint8Array
  payloadHash: Uint8Array
  createdAt: string
  expiresAt: string
}

export type VaultCoordinatorRestoreReason = 'new-member' | 'ttl-expired' | 'retention-quota' | 'delivery-confirmed' | 'checkpointed'
export type VaultCoordinatorPullResult =
  | { kind: 'items'; items: VaultCoordinatorItemV1[]; nextCursor: DeliverySeq; retainedFrom: DeliverySeq; latestSeq: DeliverySeq }
  | { kind: 'restoreRequired'; requestedCursor: DeliverySeq; retainedFrom: DeliverySeq; latestSeq: DeliverySeq; reason: VaultCoordinatorRestoreReason }

export function decodeVaultCoordinatorAppend(text: string): VaultCoordinatorAppendV1 {
  const input = exactRecord(text, ['version', 'vaultId', 'appendId', 'senderMemberId', 'groupEpoch', 'payload', 'payloadHash', 'sentAt', 'signature'])
  if (input.version !== 1) throw new TypeError('invalid Vault append version')
  assertVaultId(input.vaultId)
  assertOpaqueId(input.appendId, 'appendId', 128)
  assertVaultMemberId(input.senderMemberId)
  assertMlsEpoch(input.groupEpoch)
  assertTimestamp(input.sentAt, 'sentAt')
  return { version: 1, vaultId: input.vaultId, appendId: input.appendId, senderMemberId: input.senderMemberId, groupEpoch: input.groupEpoch, payload: binary(input.payload), payloadHash: hash(input.payloadHash), sentAt: input.sentAt, signature: signature(input.signature) }
}

export function decodeVaultCoordinatorPull(text: string): VaultCoordinatorPullV1 {
  const input = exactRecord(text, ['version', 'vaultId', 'recipientMemberId', 'after', 'requestedAt', 'signature'])
  if (input.version !== 1) throw new TypeError('invalid Vault pull version')
  assertVaultId(input.vaultId)
  assertVaultMemberId(input.recipientMemberId)
  assertDeliverySeq(input.after)
  assertTimestamp(input.requestedAt, 'requestedAt')
  return { version: 1, vaultId: input.vaultId, recipientMemberId: input.recipientMemberId, after: input.after, requestedAt: input.requestedAt, signature: signature(input.signature) }
}

export function decodeVaultCoordinatorAck(text: string): VaultCoordinatorAckV1 {
  const input = exactRecord(text, ['version', 'vaultId', 'recipientMemberId', 'seq', 'payloadHash', 'ackedAt', 'signature'])
  if (input.version !== 1) throw new TypeError('invalid Vault ACK version')
  assertVaultId(input.vaultId)
  assertVaultMemberId(input.recipientMemberId)
  assertDeliverySeq(input.seq)
  assertTimestamp(input.ackedAt, 'ackedAt')
  return { version: 1, vaultId: input.vaultId, recipientMemberId: input.recipientMemberId, seq: input.seq, payloadHash: hash(input.payloadHash), ackedAt: input.ackedAt, signature: signature(input.signature) }
}

export function decodeVaultCoordinatorCheckpointPut(text: string): VaultCoordinatorCheckpointPutV1 {
  const input = exactRecord(text, ['version', 'vaultId', 'writerMemberId', 'coveredSeq', 'payload', 'payloadHash', 'createdAt', 'signature'])
  if (input.version !== 1) throw new TypeError('invalid Vault checkpoint version')
  assertVaultId(input.vaultId)
  assertVaultMemberId(input.writerMemberId)
  assertDeliverySeq(input.coveredSeq)
  assertTimestamp(input.createdAt, 'createdAt')
  return { version: 1, vaultId: input.vaultId, writerMemberId: input.writerMemberId, coveredSeq: input.coveredSeq, payload: binary(input.payload), payloadHash: hash(input.payloadHash), createdAt: input.createdAt, signature: signature(input.signature) }
}

export function decodeVaultCoordinatorCheckpointPull(text: string): VaultCoordinatorCheckpointPullV1 {
  const input = exactRecord(text, ['version', 'vaultId'])
  if (input.version !== 1) throw new TypeError('invalid Vault checkpoint pull version')
  assertVaultId(input.vaultId)
  return { version: 1, vaultId: input.vaultId }
}

export function encodeVaultCoordinatorAppend(value: VaultCoordinatorAppendV1): string {
  return encodeChecked({
    ...value,
    payload: bytesToBase64url(value.payload),
    payloadHash: bytesToBase64url(value.payloadHash),
    signature: bytesToBase64url(value.signature),
  }, decodeVaultCoordinatorAppend)
}

export function encodeVaultCoordinatorPull(value: VaultCoordinatorPullV1): string {
  return encodeChecked({ ...value, signature: bytesToBase64url(value.signature) }, decodeVaultCoordinatorPull)
}

export function encodeVaultCoordinatorAck(value: VaultCoordinatorAckV1): string {
  return encodeChecked({
    ...value,
    payloadHash: bytesToBase64url(value.payloadHash),
    signature: bytesToBase64url(value.signature),
  }, decodeVaultCoordinatorAck)
}

export function encodeVaultCoordinatorCheckpointPut(value: VaultCoordinatorCheckpointPutV1): string {
  return encodeChecked({ ...value, payload: bytesToBase64url(value.payload), payloadHash: bytesToBase64url(value.payloadHash), signature: bytesToBase64url(value.signature) }, decodeVaultCoordinatorCheckpointPut)
}

export function encodeVaultCoordinatorCheckpointPull(value: VaultCoordinatorCheckpointPullV1): string {
  return encodeChecked({ ...value }, decodeVaultCoordinatorCheckpointPull)
}

export function encodeVaultCoordinatorCheckpoint(value: VaultCoordinatorCheckpointV1 | null): string {
  return JSON.stringify(value === null ? null : { ...value, payload: bytesToBase64url(value.payload), payloadHash: bytesToBase64url(value.payloadHash) })
}

export function decodeVaultCoordinatorCheckpoint(text: string): VaultCoordinatorCheckpointV1 | null {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('Vault Coordinator checkpoint response is not JSON') }
  if (value === null) return null
  const input = exactValueRecord(value, ['version', 'vaultId', 'writerMemberId', 'coveredSeq', 'payload', 'payloadHash', 'createdAt'], 'Vault Coordinator checkpoint response')
  if (input.version !== 1) throw new TypeError('invalid Vault checkpoint response version')
  assertVaultId(input.vaultId)
  assertVaultMemberId(input.writerMemberId)
  assertDeliverySeq(input.coveredSeq)
  assertTimestamp(input.createdAt, 'createdAt')
  return { version: 1, vaultId: input.vaultId, writerMemberId: input.writerMemberId, coveredSeq: input.coveredSeq, payload: binary(input.payload), payloadHash: hash(input.payloadHash), createdAt: input.createdAt }
}

export function encodeVaultCoordinatorOwnedVaults(values: VaultCoordinatorOwnedVaultV1[]): string {
  return JSON.stringify({ vaults: values })
}

export function decodeVaultCoordinatorOwnedVaults(text: string): VaultCoordinatorOwnedVaultV1[] {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('Vault Coordinator owned Vault response is not JSON') }
  const input = exactValueRecord(value, ['vaults'], 'Vault Coordinator owned Vault response')
  if (!Array.isArray(input.vaults)) throw new TypeError('Vault Coordinator owned Vault list is invalid')
  return input.vaults.map(entry => {
    const item = exactValueRecord(entry, Object.prototype.hasOwnProperty.call(entry as object, 'checkpointSeq') ? ['vaultId', 'latestSeq', 'checkpointSeq'] : ['vaultId', 'latestSeq'], 'Vault Coordinator owned Vault')
    assertVaultId(item.vaultId)
    assertDeliverySeq(item.latestSeq)
    if (item.checkpointSeq !== undefined) assertDeliverySeq(item.checkpointSeq)
    return { vaultId: item.vaultId, latestSeq: item.latestSeq, ...(item.checkpointSeq === undefined ? {} : { checkpointSeq: item.checkpointSeq }) }
  })
}

export function vaultCoordinatorAppendSigningBytes(value: Omit<VaultCoordinatorAppendV1, 'payload' | 'signature'>): Uint8Array {
  return canonicalBytes({ version: 1, kind: 'biset.vault.append', vaultId: value.vaultId, appendId: value.appendId, senderMemberId: value.senderMemberId, groupEpoch: value.groupEpoch, payloadHash: bytesToBase64url(value.payloadHash), sentAt: value.sentAt })
}

export function vaultCoordinatorPullSigningBytes(value: Omit<VaultCoordinatorPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({ version: 1, kind: 'biset.vault.pull', vaultId: value.vaultId, recipientMemberId: value.recipientMemberId, after: value.after, requestedAt: value.requestedAt })
}

export function vaultCoordinatorAckSigningBytes(value: Omit<VaultCoordinatorAckV1, 'signature'>): Uint8Array {
  return canonicalBytes({ version: 1, kind: 'biset.vault.ack', vaultId: value.vaultId, recipientMemberId: value.recipientMemberId, seq: value.seq, payloadHash: bytesToBase64url(value.payloadHash), ackedAt: value.ackedAt })
}

export function vaultCoordinatorCheckpointSigningBytes(value: Omit<VaultCoordinatorCheckpointPutV1, 'payload' | 'signature'>): Uint8Array {
  return canonicalBytes({ version: 1, kind: 'biset.vault.checkpoint', vaultId: value.vaultId, writerMemberId: value.writerMemberId, coveredSeq: value.coveredSeq, payloadHash: bytesToBase64url(value.payloadHash), createdAt: value.createdAt })
}

export function encodeVaultCoordinatorPullResult(value: VaultCoordinatorPullResult): string {
  if (value.kind === 'restoreRequired') return JSON.stringify(value)
  return JSON.stringify({ ...value, items: value.items.map(item => ({ ...item, payload: bytesToBase64url(item.payload), payloadHash: bytesToBase64url(item.payloadHash) })) })
}

export function decodeVaultCoordinatorPullResult(text: string): VaultCoordinatorPullResult {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('Vault Coordinator pull result is not JSON') }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Vault Coordinator pull result must be an object')
  if ((value as Record<string, unknown>).kind === 'restoreRequired') {
    const input = exactValueRecord(value, ['kind', 'requestedCursor', 'retainedFrom', 'latestSeq', 'reason'], 'Vault Coordinator restore result')
    assertDeliverySeq(input.requestedCursor)
    assertDeliverySeq(input.retainedFrom)
    assertDeliverySeq(input.latestSeq)
    if (!isRestoreReason(input.reason)) throw new TypeError('Vault Coordinator restore reason is invalid')
    return { kind: 'restoreRequired', requestedCursor: input.requestedCursor, retainedFrom: input.retainedFrom, latestSeq: input.latestSeq, reason: input.reason }
  }
  const input = exactValueRecord(value, ['kind', 'items', 'nextCursor', 'retainedFrom', 'latestSeq'], 'Vault Coordinator items result')
  if (input.kind !== 'items' || !Array.isArray(input.items)) throw new TypeError('Vault Coordinator items result is invalid')
  assertDeliverySeq(input.nextCursor)
  assertDeliverySeq(input.retainedFrom)
  assertDeliverySeq(input.latestSeq)
  const items = input.items.map((entry): VaultCoordinatorItemV1 => {
    const item = exactValueRecord(entry, ['version', 'vaultId', 'seq', 'groupEpoch', 'payload', 'payloadHash', 'createdAt', 'expiresAt'], 'Vault Coordinator item')
    if (item.version !== 1) throw new TypeError('invalid Vault Coordinator item version')
    assertVaultId(item.vaultId)
    assertDeliverySeq(item.seq)
    assertMlsEpoch(item.groupEpoch)
    assertTimestamp(item.createdAt, 'createdAt')
    assertTimestamp(item.expiresAt, 'expiresAt')
    return { version: 1, vaultId: item.vaultId, seq: item.seq, groupEpoch: item.groupEpoch, payload: binary(item.payload), payloadHash: hash(item.payloadHash), createdAt: item.createdAt, expiresAt: item.expiresAt }
  })
  return { kind: 'items', items, nextCursor: input.nextCursor, retainedFrom: input.retainedFrom, latestSeq: input.latestSeq }
}

function encodeChecked<T>(wire: Record<string, unknown>, decode: (text: string) => T): string {
  const text = JSON.stringify(wire)
  decode(text)
  return text
}

function isRestoreReason(value: unknown): value is VaultCoordinatorRestoreReason {
  return value === 'new-member' || value === 'ttl-expired' || value === 'retention-quota' || value === 'delivery-confirmed' || value === 'checkpointed'
}

function exactRecord(text: string, keys: string[]): Record<string, unknown> {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('Vault Coordinator body is not JSON') }
  return exactValueRecord(value, keys, 'Vault Coordinator body')
}

function exactValueRecord(value: unknown, keys: string[], name: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`)
  const record = value as Record<string, unknown>
  const actual = Object.keys(record).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new TypeError(`${name} has unexpected fields`)
  return record
}

function binary(value: unknown): Uint8Array {
  if (typeof value !== 'string') throw new TypeError('Vault Coordinator binary field must be base64url')
  return base64urlToBytes(value)
}

function hash(value: unknown): Uint8Array {
  const result = binary(value)
  if (result.length !== 32) throw new TypeError('payloadHash must contain 32 bytes')
  return result
}

function signature(value: unknown): Uint8Array {
  const result = binary(value)
  if (result.length !== 64) throw new TypeError('member signature must contain 64 bytes')
  return result
}

function assertTimestamp(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new TypeError(`${name} must be a canonical ISO timestamp`)
}
