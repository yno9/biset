/** Vault-to-MIMI data-plane boundary.  MLS state and retry ciphertext live
 * behind the supplied session so a lost HTTP response cannot create a second
 * ciphertext for one delivery ID. */
import { bytesToBase64url, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import type { DeliverySeq, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { DeliveriesPullRequest, MimiDeliveryEntry, VaultCheckpointManifest } from '../mimi/protocol-types.ts'
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
export interface MimiVaultDecodedBatch {
  deliveries: MimiVaultPayload[]
  checkpoints: MimiVaultCheckpointPayload[]
  latestSequence: number
  /** True when a checkpoint manifest was observed in this batch, whether or
   * not its chunks could be reconstructed into `checkpoints` above -- see
   * that field's own note in `decodeMimiVaultBatch`'s doc comment for why a
   * manifest can be unreconstructable without being an error. A caller
   * deciding whether to CREATE a new checkpoint should gate on this, not on
   * `checkpoints.length`, or it will keep creating redundant ones every
   * sync round whenever the existing one can never be reconstructed. */
  sawCheckpointManifest: boolean
}
export interface MimiVaultSynchronizationResult {
  appendedEntryIds: VaultEventId[]
  ingestedSequences: DeliverySeq[]
  checkpoints: MimiVaultCheckpointPayload[]
  latestSequence: number
  sawCheckpointManifest: boolean
}

/** Collects every bounded pull page before chunk reconstruction. A 100MB
 * checkpoint can span 256 chunks while a provider page contains only 32. */
export async function pullMimiVaultPages(
  pull: (request: DeliveriesPullRequest) => Promise<MimiDeliveryEntry[]>,
  sign: (unsigned: Omit<DeliveriesPullRequest, 'signature'>) => Promise<Uint8Array> | Uint8Array,
  input: Omit<DeliveriesPullRequest, 'afterSeq' | 'signature'>,
  afterSeq = 0,
  pageSize = 32,
): Promise<MimiDeliveryEntry[]> {
  if (!Number.isSafeInteger(afterSeq) || afterSeq < 0 || !Number.isSafeInteger(pageSize) || pageSize < 1) throw new TypeError('MIMI Vault pull cursor is invalid')
  const all: MimiDeliveryEntry[] = []
  let cursor = afterSeq
  for (let pages = 0; pages < 1024; pages++) {
    const unsigned = { ...input, afterSeq: cursor }
    const page = await pull({ ...unsigned, signature: await sign(unsigned) })
    if (page.some((entry, index) => !Number.isSafeInteger(entry.seq) || entry.seq <= cursor || (index > 0 && entry.seq <= page[index - 1]!.seq))) throw new TypeError('MIMI Vault pull page is not strictly ordered')
    all.push(...page)
    if (page.length < pageSize) return all
    cursor = page.at(-1)!.seq
  }
  throw new Error('MIMI Vault pull exceeded its bounded page count')
}

/** One MIMI Vault pass: obtain all pages, apply a newest checkpoint first,
 * ingest complete encrypted delivery packs, then flush local outbox work.
 * The callbacks keep Vault projection and MLS private keys out of this
 * transport module. */
export async function synchronizeMimiVault(input: {
  pull: (request: DeliveriesPullRequest) => Promise<MimiDeliveryEntry[]>
  signPull: (unsigned: Omit<DeliveriesPullRequest, 'signature'>) => Promise<Uint8Array> | Uint8Array
  pullRequest: Omit<DeliveriesPullRequest, 'afterSeq' | 'signature'>
  receiver: MimiVaultMlsReceiver
  outbox: VaultDeliveryOutboxReader
  sender: MimiVaultMlsSender
  identityId: IdentityId
  ingest(payload: Uint8Array, sequence: DeliverySeq): Promise<void>
  restoreCheckpoint?(checkpoint: MimiVaultCheckpointPayload): Promise<void>
  afterSeq?: number
}): Promise<MimiVaultSynchronizationResult> {
  const entries = await pullMimiVaultPages(input.pull, input.signPull, input.pullRequest, input.afterSeq ?? 0)
  const decoded = await decodeMimiVaultBatch(entries, input.receiver)
  for (const checkpoint of decoded.checkpoints) {
    try {
      await input.restoreCheckpoint?.(checkpoint)
    } catch (error) {
      // Same reasoning as the ingest loop just below: one already-decoded
      // delivery failing to apply locally (e.g. a local-projection identity
      // conflict) must not re-block every OTHER item in this batch, or any
      // later batch, forever -- the cursor still advances past this pull
      // regardless (decoded.latestSequence, computed above, independent of
      // what ingest/restoreCheckpoint do), so a skip here is permanent,
      // same as an undecryptable entry: there is no "try again next poll"
      // for content the hub already delivered once (found live, 2026-09-02,
      // for the ingest loop's own version of this: "[mimi-vault/poll] vault
      // message.add conflicts with an existing email", blocking the whole
      // round on every single poll from then on).
      console.warn('[mimi-vault/checkpoint] restore failed, skipping:', error instanceof Error ? error.message : error)
    }
  }
  const ingestedSequences: DeliverySeq[] = []
  for (const delivery of decoded.deliveries) {
    const sequence = mimiVaultSequence(delivery.finalSequence)
    try {
      await input.ingest(delivery.payload, sequence)
      ingestedSequences.push(sequence)
    } catch (error) {
      console.warn('[mimi-vault/ingest] delivery could not be applied locally, skipping:', error instanceof Error ? error.message : error)
    }
  }
  let flushed = await flushMimiVaultOutbox(input.outbox, input.sender, input.identityId)
  if (flushed.failedEntryId && flushed.failureReason?.includes('epochTooOld')) {
    // A sibling device's own commit can land between this pull and this
    // send -- the hub rejects an application message against a stale
    // epoch, and by construction this device only just discovered whatever
    // commit made it stale (the pull above already happened before that
    // commit was known). One more pull+decode round catches this device's
    // own MLS state up to the CURRENT epoch before retrying, rather than
    // treating an ordinary, expected race as a hard failure that leaves
    // the outbox stuck until something else happens to retry it (found
    // live, 2026-09-02, reproduced against real production: a device's own
    // send failed with epochTooOld immediately after a sibling device
    // joined, until this device separately re-pulled first).
    const followUp = await pullMimiVaultPages(input.pull, input.signPull, input.pullRequest, decoded.latestSequence)
    const followUpDecoded = await decodeMimiVaultBatch(followUp, input.receiver)
    for (const checkpoint of followUpDecoded.checkpoints) await input.restoreCheckpoint?.(checkpoint)
    for (const delivery of followUpDecoded.deliveries) {
      const sequence = mimiVaultSequence(delivery.finalSequence)
      await input.ingest(delivery.payload, sequence)
      ingestedSequences.push(sequence)
    }
    decoded.checkpoints.push(...followUpDecoded.checkpoints)
    decoded.latestSequence = Math.max(decoded.latestSequence, followUpDecoded.latestSequence)
    decoded.sawCheckpointManifest ||= followUpDecoded.sawCheckpointManifest
    flushed = await flushMimiVaultOutbox(input.outbox, input.sender, input.identityId)
  }
  if (flushed.failedEntryId) throw new Error(`MIMI Vault outbox append failed: ${flushed.failureReason ?? flushed.failedEntryId}`)
  return { appendedEntryIds: flushed.appendedEntryIds, ingestedSequences, checkpoints: decoded.checkpoints, latestSequence: decoded.latestSequence, sawCheckpointManifest: decoded.sawCheckpointManifest }
}

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
 * pages.  Tombstoned application rows are deliberately ignored.
 *
 * A manifest whose chunks cannot be reconstructed (missing or disagreeing
 * with the manifest) is skipped, not thrown -- the device that ORIGINALLY
 * created a checkpoint sees exactly this on every later re-pull that
 * includes it: `receiver.receive` recognizes that chunk as its own already-
 * sent echo (`ownApplicationHashes`) and returns undefined for it, forever,
 * while the checkpoint manifest itself decodes normally every time (found
 * live, 2026-09-02) -- there is no way to distinguish that from genuine
 * corruption from here, but a creating device never needs to reconstruct
 * its own checkpoint's payload from chunks anyway (it already has the
 * plaintext it built the checkpoint from), so treating it as merely
 * unreconstructable -- not a hard failure that would otherwise brick
 * syncing permanently -- is correct either way. */
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
      let plaintext: Uint8Array | undefined
      try {
        plaintext = await receiver.receive(entry)
      } catch (error) {
        // An application message's secret-tree generation can fall outside
        // this device's retained window -- MLS forward secrecy deliberately
        // discards a skipped generation's key once enough later generations
        // (from the SAME sender) have been processed, so this is not a bug
        // to retry: the plaintext is gone forever, no matter how many more
        // times this same entry is re-pulled. Throwing here (as receive()
        // itself still does, for every caller that isn't this loop) used to
        // abort the ENTIRE batch on this one permanently-undecryptable
        // entry, forever, on every single poll from here on -- even the
        // rest of THIS SAME batch, let alone anything genuinely new next
        // time, never got a chance to be processed (found live, 2026-09-02:
        // "[mimi-vault/poll] Desired gen in the past", repeating every poll,
        // with real newer content already sitting on the hub the whole
        // time). Skipping just this one entry is the only thing to do with
        // an already-lost message; every other entry in this batch, and
        // every batch after it, deserves the chance this one no longer can
        // use.
        console.warn('[mimi-vault/decode] application entry is permanently undecryptable, skipping:', error instanceof Error ? error.message : error)
        continue
      }
      // A session returns undefined for this device's echoed PrivateMessage:
      // the sender chain has already consumed that generation locally.
      if (plaintext === undefined) continue
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
    if (values && values.length === manifest.chunkCount) {
      const payload = joinMimiVaultChunks(values.map(value => value.chunk))
      if (equalBytes(sha256Bytes(payload), manifest.payloadHash) && values.every(value => value.chunk.count === manifest.chunkCount && equalBytes(value.chunk.payloadHash, manifest.payloadHash))) {
        checkpoints.push({ transferId: manifest.transferId, payload, finalSequence: Math.max(seq, ...values.map(value => value.seq)), manifest: { ...manifest, payloadHash: manifest.payloadHash.slice() } })
      }
    }
    claimed.add(manifest.transferId)
  }
  const deliveries: MimiVaultPayload[] = []
  for (const [transferId, values] of chunks) {
    if (claimed.has(transferId)) continue
    deliveries.push({ transferId, payload: joinMimiVaultChunks(values.map(value => value.chunk)), finalSequence: Math.max(...values.map(value => value.seq)) })
  }
  deliveries.sort((left, right) => left.finalSequence - right.finalSequence)
  checkpoints.sort((left, right) => left.finalSequence - right.finalSequence)
  return { deliveries, checkpoints, latestSequence, sawCheckpointManifest: manifests.length > 0 }
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
