/** Vault-to-MIMI data-plane boundary.  MLS state and retry ciphertext live
 * behind the supplied session so a lost HTTP response cannot create a second
 * ciphertext for one delivery ID. */
import { bytesToBase64url, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import type { DeliverySeq, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { MimiDeliveryEntry, VaultCheckpointManifest } from '../mimi/protocol-types.ts'
import { decodeMimiVaultChunk, encodeMimiVaultChunk, joinMimiVaultChunks, splitMimiVaultPayload, type MimiVaultChunk } from './mimi-vault-chunks.ts'
import type { VaultDeliveryOutboxReader } from './store.ts'

export interface MimiVaultMlsSender {
  /** Encrypt, persist the retryable MLS transition, and submit this chunk. */
  sendApplication(plaintext: Uint8Array, deliveryId: string): Promise<void>
  /** Submit the signed, hub-visible compaction boundary. */
  sendCheckpoint(manifest: VaultCheckpointManifest): Promise<void>
}
export interface MimiVaultMlsReceiver {
  /** Persist MLS handshake changes; return plaintext for application entries. */
  receive(entry: MimiDeliveryEntry): Promise<Uint8Array | undefined>
}
export interface MimiVaultPayload { transferId: string; payload: Uint8Array; finalSequence: number }
export interface MimiVaultCheckpointPayload extends MimiVaultPayload { manifest: VaultCheckpointManifest }
export interface MimiVaultDecodedBatch { deliveries: MimiVaultPayload[]; checkpoints: MimiVaultCheckpointPayload[]; latestSequence: number }

/** Flush local VaultDeliveryPack records as opaque MLS-encrypted MIMI chunks.
 * An outbox record leaves local storage only after all chunks are accepted. */
export async function flushMimiVaultOutbox(
  outbox: VaultDeliveryOutboxReader,
  sender: MimiVaultMlsSender,
  identityId: IdentityId,
  limit = 32,
): Promise<{ appendedEntryIds: VaultEventId[]; failedEntryId?: VaultEventId; failureReason?: string }> {
  const appendedEntryIds: VaultEventId[] = []
  for (const entry of await outbox.readDeliveryOutbox(identityId, limit)) {
    try {
      if (entry.identityId !== identityId || entry.payload.length === 0 || !equalBytes(sha256Bytes(entry.payload), entry.payloadHash)) throw new TypeError('local Vault delivery outbox entry is invalid')
      const transferId = stableTransferId(entry.entryId)
      for (const chunk of splitMimiVaultPayload(entry.payload, transferId)) await sender.sendApplication(encodeMimiVaultChunk(chunk), stableDeliveryId(entry.entryId, chunk.ordinal))
      await outbox.removeDeliveryOutbox(identityId, entry.entryId)
      appendedEntryIds.push(entry.entryId)
    } catch (error) {
      await outbox.noteDeliveryOutboxAttempt(identityId, entry.entryId)
      return { appendedEntryIds, failedEntryId: entry.entryId, failureReason: error instanceof Error ? error.message : String(error) }
    }
  }
  return { appendedEntryIds }
}

/** Encrypt chunks first, then publish the sole hub-visible checkpoint cue. */
export async function sendMimiVaultCheckpoint(payload: Uint8Array, coveredSeq: number, sender: MimiVaultMlsSender): Promise<VaultCheckpointManifest> {
  if (!Number.isSafeInteger(coveredSeq) || coveredSeq < 0) throw new TypeError('Vault checkpoint covered sequence is invalid')
  const transferId = bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))
  const chunks = splitMimiVaultPayload(payload, transferId)
  for (const chunk of chunks) await sender.sendApplication(encodeMimiVaultChunk(chunk), stableDeliveryId(transferId, chunk.ordinal))
  const manifest: VaultCheckpointManifest = { coveredSeq, transferId, chunkCount: chunks.length, payloadHash: chunks[0]!.payloadHash.slice() }
  await sender.sendCheckpoint(manifest)
  return manifest
}

/** Reconstructs complete Vault transfers from one or more contiguous pull
 * pages.  Tombstoned application rows are deliberately ignored. */
export async function decodeMimiVaultBatch(entries: readonly MimiDeliveryEntry[], receiver: MimiVaultMlsReceiver): Promise<MimiVaultDecodedBatch> {
  const chunks = new Map<string, Array<{ chunk: MimiVaultChunk; seq: number }>>()
  const manifests: Array<{ manifest: VaultCheckpointManifest; seq: number }> = []
  let latestSequence = 0
  for (const entry of entries) {
    latestSequence = Math.max(latestSequence, entry.seq)
    if (entry.kind === 'vaultCheckpoint') {
      if (!entry.vaultCheckpoint) throw new TypeError('Vault checkpoint delivery has no manifest')
      manifests.push({ manifest: entry.vaultCheckpoint, seq: entry.seq })
    } else if (entry.kind !== 'application') {
      await receiver.receive(entry)
    } else if (entry.payload.length !== 0) {
      const plaintext = await receiver.receive(entry)
      if (plaintext === undefined) throw new TypeError('MLS application delivery did not decrypt')
      const chunk = decodeMimiVaultChunk(plaintext)
      const current = chunks.get(chunk.transferId) ?? []
      current.push({ chunk, seq: entry.seq })
      chunks.set(chunk.transferId, current)
    }
  }
  const checkpoints: MimiVaultCheckpointPayload[] = []
  const claimed = new Set<string>()
  for (const { manifest, seq } of manifests) {
    const values = chunks.get(manifest.transferId)
    if (!values || values.length !== manifest.chunkCount) throw new TypeError('Vault checkpoint chunks are incomplete')
    const payload = joinMimiVaultChunks(values.map(value => value.chunk))
    if (!equalBytes(sha256Bytes(payload), manifest.payloadHash) || values.some(value => value.chunk.count !== manifest.chunkCount || !equalBytes(value.chunk.payloadHash, manifest.payloadHash))) throw new TypeError('Vault checkpoint manifest disagrees with chunks')
    checkpoints.push({ transferId: manifest.transferId, payload, finalSequence: Math.max(seq, ...values.map(value => value.seq)), manifest: { ...manifest, payloadHash: manifest.payloadHash.slice() } })
    claimed.add(manifest.transferId)
  }
  const deliveries: MimiVaultPayload[] = []
  for (const [transferId, values] of chunks) {
    if (claimed.has(transferId)) continue
    deliveries.push({ transferId, payload: joinMimiVaultChunks(values.map(value => value.chunk)), finalSequence: Math.max(...values.map(value => value.seq)) })
  }
  deliveries.sort((left, right) => left.finalSequence - right.finalSequence)
  checkpoints.sort((left, right) => left.finalSequence - right.finalSequence)
  return { deliveries, checkpoints, latestSequence }
}

export function mimiVaultSequence(sequence: number): DeliverySeq {
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new TypeError('MIMI Vault delivery sequence is invalid')
  return String(sequence) as DeliverySeq
}
function stableTransferId(entryId: string): string { return bytesToBase64url(sha256Bytes(new TextEncoder().encode(`biset/mimi-vault-transfer/v1:${entryId}`))) }
function stableDeliveryId(seed: string, ordinal: number): string {
  if (!Number.isSafeInteger(ordinal) || ordinal < 0) throw new TypeError('Vault chunk ordinal is invalid')
  return bytesToBase64url(sha256Bytes(new TextEncoder().encode(`biset/mimi-vault-delivery/v1:${seed}:${ordinal}`)))
}
