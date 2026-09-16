/** Opaque, hash-checked chunks used by Vault Sync state responses. */
import { bytesToBase64url, canonicalBytes, sha256Bytes } from '../../../protocol/canonical.ts'

export const VAULT_SYNC_CHUNK_BYTES = 128 * 1024
export interface VaultSyncChunk { transferId: string; ordinal: number; count: number; payloadHash: Uint8Array; payload: Uint8Array }

export function splitVaultSyncPayload(payload: Uint8Array, transferId = bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))): VaultSyncChunk[] {
  if (payload.length === 0 || !/^[A-Za-z0-9_-]{16,128}$/.test(transferId)) throw new TypeError('Vault chunk input is invalid')
  const count = Math.ceil(payload.length / VAULT_SYNC_CHUNK_BYTES)
  if (count > 256) throw new RangeError('Vault payload exceeds chunk limit')
  const payloadHash = sha256Bytes(payload)
  return Array.from({ length: count }, (_, ordinal) => ({ transferId, ordinal, count, payloadHash, payload: payload.slice(ordinal * VAULT_SYNC_CHUNK_BYTES, Math.min(payload.length, (ordinal + 1) * VAULT_SYNC_CHUNK_BYTES)) }))
}

export function encodeVaultSyncChunk(value: VaultSyncChunk): Uint8Array {
  assertChunk(value)
  return canonicalBytes({ version: 1, transferId: value.transferId, ordinal: value.ordinal, count: value.count, payloadHash: bytesToBase64url(value.payloadHash), payload: bytesToBase64url(value.payload) })
}

function assertChunk(value: VaultSyncChunk): void {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(value.transferId) || !Number.isSafeInteger(value.ordinal) || !Number.isSafeInteger(value.count) || value.ordinal < 0 || value.count < 1 || value.ordinal >= value.count || value.count > 256 || value.payload.length < 1 || value.payload.length > VAULT_SYNC_CHUNK_BYTES || value.payloadHash.length !== 32) throw new TypeError('Vault chunk is invalid')
}
