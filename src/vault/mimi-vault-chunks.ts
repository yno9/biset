/** Opaque Vault payload chunks carried inside MLS application messages. */
import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes, sha256Bytes } from '../protocol/canonical.ts'

export const MIMI_VAULT_CHUNK_BYTES = 700 * 1024
export interface MimiVaultChunk { transferId: string; ordinal: number; count: number; payloadHash: Uint8Array; payload: Uint8Array }

export function splitMimiVaultPayload(payload: Uint8Array, transferId = bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))): MimiVaultChunk[] {
  if (payload.length === 0 || !/^[A-Za-z0-9_-]{16,128}$/.test(transferId)) throw new TypeError('Vault chunk input is invalid')
  const count = Math.ceil(payload.length / MIMI_VAULT_CHUNK_BYTES)
  if (count > 256) throw new RangeError('Vault payload exceeds chunk limit')
  const payloadHash = sha256Bytes(payload)
  return Array.from({ length: count }, (_, ordinal) => ({ transferId, ordinal, count, payloadHash, payload: payload.slice(ordinal * MIMI_VAULT_CHUNK_BYTES, Math.min(payload.length, (ordinal + 1) * MIMI_VAULT_CHUNK_BYTES)) }))
}
export function encodeMimiVaultChunk(value: MimiVaultChunk): Uint8Array {
  assertChunk(value)
  return canonicalBytes({ version: 1, transferId: value.transferId, ordinal: value.ordinal, count: value.count, payloadHash: bytesToBase64url(value.payloadHash), payload: bytesToBase64url(value.payload) })
}
export function decodeMimiVaultChunk(bytes: Uint8Array): MimiVaultChunk {
  let input: unknown; try { input = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('Vault chunk is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Vault chunk is invalid')
  const value = input as Record<string, unknown>
  if (value.version !== 1 || typeof value.transferId !== 'string' || !Number.isSafeInteger(value.ordinal) || !Number.isSafeInteger(value.count) || typeof value.payloadHash !== 'string' || typeof value.payload !== 'string') throw new TypeError('Vault chunk is invalid')
  const chunk: MimiVaultChunk = { transferId: value.transferId, ordinal: value.ordinal as number, count: value.count as number, payloadHash: base64urlToBytes(value.payloadHash), payload: base64urlToBytes(value.payload) }
  assertChunk(chunk); if (!equalBytes(bytes, encodeMimiVaultChunk(chunk))) throw new TypeError('Vault chunk is not canonical'); return chunk
}
export function joinMimiVaultChunks(chunks: MimiVaultChunk[]): Uint8Array {
  if (chunks.length === 0) throw new TypeError('Vault chunks are empty')
  const first = chunks[0]!; if (chunks.length !== first.count) throw new TypeError('Vault chunks are incomplete')
  const sorted = [...chunks].sort((a, b) => a.ordinal - b.ordinal)
  if (sorted.some((chunk, ordinal) => chunk.transferId !== first.transferId || chunk.count !== first.count || chunk.ordinal !== ordinal || !equalBytes(chunk.payloadHash, first.payloadHash))) throw new TypeError('Vault chunks disagree')
  const result = new Uint8Array(sorted.reduce((sum, chunk) => sum + chunk.payload.length, 0)); let offset = 0; for (const chunk of sorted) { result.set(chunk.payload, offset); offset += chunk.payload.length }
  if (!equalBytes(sha256Bytes(result), first.payloadHash)) throw new TypeError('Vault chunk payload hash is invalid'); return result
}
/** Sends ciphertext-ready chunks in order, then commits the small manifest.
 * The caller encrypts each encoded chunk as its own MLS PrivateMessage and
 * signs the normal MIMI client request; this module never receives MLS keys. */
export async function sendMimiVaultCheckpoint(
  payload: Uint8Array,
  coveredSeq: number,
  sender: { sendChunk(chunk: Uint8Array, deliveryId: string): Promise<void>; sendManifest(manifest: { coveredSeq: number; transferId: string; chunkCount: number; payloadHash: Uint8Array }): Promise<void> },
  transferId = bytesToBase64url(crypto.getRandomValues(new Uint8Array(32))),
): Promise<{ coveredSeq: number; transferId: string; chunkCount: number; payloadHash: Uint8Array }> {
  if (!Number.isSafeInteger(coveredSeq) || coveredSeq < 0) throw new TypeError('Vault checkpoint covered sequence is invalid')
  const chunks = splitMimiVaultPayload(payload, transferId)
  for (const chunk of chunks) await sender.sendChunk(encodeMimiVaultChunk(chunk), `${transferId}-${chunk.ordinal}`)
  const manifest = { coveredSeq, transferId, chunkCount: chunks.length, payloadHash: chunks[0]!.payloadHash.slice() }
  await sender.sendManifest(manifest)
  return manifest
}
function assertChunk(value: MimiVaultChunk): void { if (!/^[A-Za-z0-9_-]{16,128}$/.test(value.transferId) || !Number.isSafeInteger(value.ordinal) || !Number.isSafeInteger(value.count) || value.ordinal < 0 || value.count < 1 || value.ordinal >= value.count || value.count > 256 || value.payload.length < 1 || value.payload.length > MIMI_VAULT_CHUNK_BYTES || value.payloadHash.length !== 32) throw new TypeError('Vault chunk is invalid') }
