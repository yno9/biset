/** Vault-to-MIMI data-plane boundary.  MLS state and retry ciphertext live
 * behind the supplied session so a lost HTTP response cannot create a second
 * ciphertext for one delivery ID. */
import { bytesToBase64url, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import type { DeliverySeq, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { DeliveriesPullRequest, MimiDeliveryEntry, VaultCheckpointManifest } from '../mimi/protocol-types.ts'
import { decodeMimiVaultChunk, encodeMimiVaultChunk, joinMimiVaultChunks, splitMimiVaultPayload, type MimiVaultChunk } from './mimi-vault-chunks.ts'
import type { VaultDeliveryOutboxReader } from './store.ts'

/** Everything one sync round could not fully apply, as data instead of a
 * side-effecting console call -- a caller can inspect this to decide things
 * console output alone cannot drive, e.g. gating checkpoint auto-recreation
 * on "this round saw no unresolved gaps" instead of just "no manifest",
 * which is what let a device with an incomplete local Vault (itself missing
 * content because of an earlier gap) confidently publish a checkpoint that
 * poisoned siblings restoring from it (found live, 2026-09-02). Every kind
 * here is a PERMANENT loss for this round, never a "try again next poll"
 * situation -- see each recovery strategy's own comment for why. */
export interface MimiVaultSyncGap {
  kind: 'undecryptable-application' | 'unverifiable-commit' | 'unreconstructed-checkpoint' | 'checkpoint-restore-failed' | 'ingest-failed' | 'outbox-flush-failed'
  detail: string
}
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
  /** Every manifest seen in this batch whose chunks could NOT be
   * reconstructed into `checkpoints` -- `recoverSplitCheckpoints`'s own
   * signal to retry with a wider pull window (see its own note on why: the
   * chunk and manifest are submitted as separate, non-atomic deliveries, so
   * they can land in different sync rounds). Includes the device's OWN
   * just-sent checkpoint too (its chunks echo back as `undefined`, so it
   * never reconstructs from this side either) -- that case is harmless, not
   * a bug, but this function has no way to tell the two apart, so it is
   * `recoverSplitCheckpoints`'s job (not this one's) to hedge in its own gap
   * text once the wider retry has also failed. */
  unreconstructedCheckpoints: Array<{ manifest: VaultCheckpointManifest; seq: number }>
  /** Losses discovered while decoding THIS batch alone -- undecryptable
   * application entries and unverifiable commits. Does not include anything
   * about `unreconstructedCheckpoints` above; that only becomes a genuine
   * gap once `recoverSplitCheckpoints`'s wider pull has also failed to
   * recover it. */
  gaps: MimiVaultSyncGap[]
}
export interface MimiVaultSynchronizationResult {
  appendedEntryIds: VaultEventId[]
  ingestedSequences: DeliverySeq[]
  checkpoints: MimiVaultCheckpointPayload[]
  latestSequence: number
  sawCheckpointManifest: boolean
  /** Everything this round could not fully apply, across every recovery
   * strategy attempted. Empty does not mean "nothing was ever wrong this
   * round" -- it means every strategy that hit something recovered it (a
   * split checkpoint reconstructed on retry, an epochTooOld outbox flush
   * that succeeded on its follow-up attempt, ...). A caller deciding
   * whether this device's own local state is trustworthy enough to publish
   * (e.g. before auto-recreating a checkpoint) should gate on THIS being
   * empty, not on `sawCheckpointManifest` alone. */
  gaps: MimiVaultSyncGap[]
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

/** Named recovery strategy: a checkpoint's chunk(s) and its manifest are
 * separate, non-atomic deliveries (sendMimiVaultCheckpoint sends the
 * chunk(s) first, then the manifest in its own follow-up call) -- if this
 * device's pull window starts partway between them (a long-suspended tab
 * waking up, or a sibling's SSE-triggered pull landing in that exact gap),
 * the manifest arrives with no matching chunk in the batch and can never be
 * reconstructed from that batch alone. Before this existed, that was
 * silently unrecoverable forever: the delivery cursor still advances past
 * the manifest, so no later poll would ever re-pull it either (found live,
 * 2026-09-02: a device stuck for hours with an empty inbox and zero console
 * output -- decodeMimiVaultBatch's own "unreconstructable manifest" case was
 * deliberately silent, written for the checkpoint's OWN creator seeing its
 * echoed chunks skip, never audited for what it means when a DIFFERENT
 * device hits the same code path for a real gap). One retry, pulling from
 * well before the earliest unreconstructed manifest instead of from this
 * round's own cursor, catches the ordinary case (chunk and manifest split by
 * one poll boundary) without needing to persist any cross-round state.
 * Mutates `decoded.checkpoints` in place with anything recovered. */
async function recoverSplitCheckpoints(
  decoded: MimiVaultDecodedBatch,
  ctx: {
    pull: (request: DeliveriesPullRequest) => Promise<MimiDeliveryEntry[]>
    signPull: (unsigned: Omit<DeliveriesPullRequest, 'signature'>) => Promise<Uint8Array> | Uint8Array
    pullRequest: Omit<DeliveriesPullRequest, 'afterSeq' | 'signature'>
    receiver: MimiVaultMlsReceiver
    alreadyPulledFrom: number
  },
): Promise<MimiVaultSyncGap[]> {
  if (!decoded.unreconstructedCheckpoints.length) return []
  // Pulls from well before the earliest unreconstructed manifest -- but
  // `pull` has no upper bound, so this necessarily re-fetches everything
  // THIS round already pulled too. Filtering the retry pull down to entries
  // strictly before this round's own starting point avoids ever handing an
  // already-processed entry to `receiver.receive` a second time (MLS
  // forward secrecy has already discarded an already-decrypted application
  // message's generation key -- re-decrypting it would fail and log a
  // spurious "permanently undecryptable" warning for a message that, in
  // fact, decrypted fine the first time). Correlated directly against the
  // already-known manifests here, not through a second decodeMimiVaultBatch
  // call -- that function only correlates a manifest against chunks it sees
  // in the SAME call, and the retry batch (by construction) never contains
  // the manifest itself again.
  const CHECKPOINT_RETRY_MARGIN = 64
  const earliestSeq = Math.min(...decoded.unreconstructedCheckpoints.map(u => u.seq))
  const retryFrom = Math.max(0, earliestSeq - CHECKPOINT_RETRY_MARGIN)
  const retryEntries = (await pullMimiVaultPages(ctx.pull, ctx.signPull, ctx.pullRequest, retryFrom))
    .filter(entry => entry.seq <= ctx.alreadyPulledFrom)
  const retryChunks = new Map<string, Array<{ chunk: MimiVaultChunk; seq: number }>>()
  for (const entry of retryEntries) {
    if (entry.kind !== 'application' || entry.payload.length === 0) continue
    let plaintext: Uint8Array | undefined
    try {
      plaintext = await ctx.receiver.receive(entry)
    } catch {
      continue // genuinely undecryptable here too -- nothing new to report, decodeMimiVaultBatch's own gap already covers this class of loss
    }
    if (plaintext === undefined) continue
    const chunk = decodeMimiVaultChunk(plaintext)
    const current = retryChunks.get(chunk.transferId) ?? []
    current.push({ chunk, seq: entry.seq })
    retryChunks.set(chunk.transferId, current)
  }
  const recovered = new Set<string>()
  for (const { manifest, seq } of decoded.unreconstructedCheckpoints) {
    const values = retryChunks.get(manifest.transferId)
    if (!values || values.length !== manifest.chunkCount) continue
    const payload = joinMimiVaultChunks(values.map(value => value.chunk))
    if (!equalBytes(sha256Bytes(payload), manifest.payloadHash) || !values.every(value => value.chunk.count === manifest.chunkCount && equalBytes(value.chunk.payloadHash, manifest.payloadHash))) continue
    decoded.checkpoints.push({ transferId: manifest.transferId, payload, finalSequence: Math.max(seq, ...values.map(value => value.seq)), manifest: { ...manifest, payloadHash: manifest.payloadHash.slice() } })
    recovered.add(manifest.transferId)
  }
  const stillMissing = decoded.unreconstructedCheckpoints.filter(u => !recovered.has(u.manifest.transferId))
  if (stillMissing.length) {
    console.warn('[mimi-vault/checkpoint] still unreconstructable after a wider retry pull -- if this is not this device\'s own checkpoint, the Vault will look stale/empty until a sibling device creates a fresh one:',
      stillMissing.map(u => `${u.manifest.transferId}@${u.seq}`).join(', '))
  }
  return stillMissing.map(u => ({ kind: 'unreconstructed-checkpoint', detail: `${u.manifest.transferId}@${u.seq}` }))
}

/** Named recovery strategy: restore each reconstructed checkpoint, skipping
 * (never aborting the whole batch for) any one that fails to apply locally.
 * The delivery cursor still advances past this pull regardless of what
 * `restoreCheckpoint` does, so a skip here is permanent -- there is no "try
 * again next poll" for content the hub already delivered once (found live,
 * 2026-09-02, for `ingestDeliveries`' own version of this: "vault
 * message.add conflicts with an existing email", blocking the whole round on
 * every single poll from then on). */
async function applyCheckpoints(
  checkpoints: MimiVaultCheckpointPayload[],
  restoreCheckpoint?: (checkpoint: MimiVaultCheckpointPayload) => Promise<void>,
): Promise<MimiVaultSyncGap[]> {
  const gaps: MimiVaultSyncGap[] = []
  for (const checkpoint of checkpoints) {
    try {
      await restoreCheckpoint?.(checkpoint)
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      console.warn('[mimi-vault/checkpoint] restore failed, skipping:', detail)
      gaps.push({ kind: 'checkpoint-restore-failed', detail: `${checkpoint.transferId}: ${detail}` })
    }
  }
  return gaps
}

/** Named recovery strategy: ingest each delivery, skipping (never aborting
 * the whole batch for) any one that fails to apply locally -- same
 * permanent-skip reasoning as `applyCheckpoints` above. */
async function ingestDeliveries(
  deliveries: MimiVaultPayload[],
  ingest: (payload: Uint8Array, sequence: DeliverySeq) => Promise<void>,
): Promise<{ ingestedSequences: DeliverySeq[]; gaps: MimiVaultSyncGap[] }> {
  const ingestedSequences: DeliverySeq[] = []
  const gaps: MimiVaultSyncGap[] = []
  for (const delivery of deliveries) {
    const sequence = mimiVaultSequence(delivery.finalSequence)
    try {
      await ingest(delivery.payload, sequence)
      ingestedSequences.push(sequence)
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      console.warn('[mimi-vault/ingest] delivery could not be applied locally, skipping:', detail)
      gaps.push({ kind: 'ingest-failed', detail: `seq ${sequence}: ${detail}` })
    }
  }
  return { ingestedSequences, gaps }
}

/** One MIMI Vault pass: obtain all pages, apply a newest checkpoint first,
 * ingest complete encrypted delivery packs, then flush local outbox work.
 * The callbacks keep Vault projection and MLS private keys out of this
 * transport module. Never throws -- every failure this round hits is a
 * permanent, per-item skip recorded in the returned `gaps` instead, so one
 * bad entry can never wedge the caller's poll loop or discard everything
 * else this round DID accomplish. */
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
  const alreadyPulledFrom = input.afterSeq ?? 0
  const entries = await pullMimiVaultPages(input.pull, input.signPull, input.pullRequest, alreadyPulledFrom)
  const decoded = await decodeMimiVaultBatch(entries, input.receiver)
  const gaps: MimiVaultSyncGap[] = [...decoded.gaps]

  gaps.push(...await recoverSplitCheckpoints(decoded, { pull: input.pull, signPull: input.signPull, pullRequest: input.pullRequest, receiver: input.receiver, alreadyPulledFrom }))
  gaps.push(...await applyCheckpoints(decoded.checkpoints, input.restoreCheckpoint))
  const primaryIngest = await ingestDeliveries(decoded.deliveries, input.ingest)
  const ingestedSequences = primaryIngest.ingestedSequences
  gaps.push(...primaryIngest.gaps)

  let flushed = await flushMimiVaultOutbox(input.outbox, input.sender, input.identityId)
  if (flushed.failedEntryId && flushed.failureReason?.includes('epochTooOld')) {
    // Named recovery strategy: a sibling device's own commit can land
    // between this pull and this send -- the hub rejects an application
    // message against a stale epoch, and by construction this device only
    // just discovered whatever commit made it stale (the pull above already
    // happened before that commit was known). One more pull+decode round
    // catches this device's own MLS state up to the CURRENT epoch before
    // retrying, rather than treating an ordinary, expected race as a hard
    // failure that leaves the outbox stuck until something else happens to
    // retry it (found live, 2026-09-02, reproduced against real production:
    // a device's own send failed with epochTooOld immediately after a
    // sibling device joined, until this device separately re-pulled first).
    // The follow-up batch goes through the SAME two strategies as the
    // primary round above, so a failure inside the retry degrades exactly
    // like an ordinary round would -- never silently, never fatally.
    const followUp = await pullMimiVaultPages(input.pull, input.signPull, input.pullRequest, decoded.latestSequence)
    const followUpDecoded = await decodeMimiVaultBatch(followUp, input.receiver)
    gaps.push(...followUpDecoded.gaps)
    gaps.push(...await applyCheckpoints(followUpDecoded.checkpoints, input.restoreCheckpoint))
    const followUpIngest = await ingestDeliveries(followUpDecoded.deliveries, input.ingest)
    ingestedSequences.push(...followUpIngest.ingestedSequences)
    gaps.push(...followUpIngest.gaps)
    decoded.checkpoints.push(...followUpDecoded.checkpoints)
    decoded.latestSequence = Math.max(decoded.latestSequence, followUpDecoded.latestSequence)
    decoded.sawCheckpointManifest ||= followUpDecoded.sawCheckpointManifest
    flushed = await flushMimiVaultOutbox(input.outbox, input.sender, input.identityId)
  }
  if (flushed.failedEntryId) {
    // Never throw: a stuck outbox is this round's OWN gap, not a reason to
    // discard everything else this round accomplished (checkpoints restored,
    // deliveries ingested) by unwinding the whole call with an exception.
    // The caller decides how to react to `gaps`, same as every other kind.
    gaps.push({ kind: 'outbox-flush-failed', detail: flushed.failureReason ?? flushed.failedEntryId })
  }
  return { appendedEntryIds: flushed.appendedEntryIds, ingestedSequences, checkpoints: decoded.checkpoints, latestSequence: decoded.latestSequence, sawCheckpointManifest: decoded.sawCheckpointManifest, gaps }
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
 * syncing permanently -- is correct either way. Not counted in `gaps`
 * directly; `recoverSplitCheckpoints` is the one place that turns a
 * still-missing entry from `unreconstructedCheckpoints` into an actual gap,
 * after its own wider retry has also failed. */
export async function decodeMimiVaultBatch(entries: readonly MimiDeliveryEntry[], receiver: MimiVaultMlsReceiver): Promise<MimiVaultDecodedBatch> {
  const chunks = new Map<string, Array<{ chunk: MimiVaultChunk; seq: number }>>()
  const manifests: Array<{ manifest: VaultCheckpointManifest; seq: number }> = []
  const gaps: MimiVaultSyncGap[] = []
  let latestSequence = 0
  for (const entry of entries) {
    latestSequence = Math.max(latestSequence, entry.seq)
    if (entry.kind === 'vaultCheckpoint') {
      if (!entry.vaultCheckpoint) throw new TypeError('Vault checkpoint delivery has no manifest')
      manifests.push({ manifest: entry.vaultCheckpoint, seq: entry.seq })
    } else if (entry.kind !== 'application') {
      // Unlike an application entry's undecryptable-generation case just
      // below, skipping a commit is not a clean recovery: this device's
      // local epoch can never advance past it, so every later commit and
      // application in this room will keep failing the same way from here
      // on -- this device needs a logout + restore (a fresh external-join
      // leaf) to use this room again. Still better than the alternative:
      // before this, one unverifiable commit aborted the WHOLE batch and
      // repeated the identical error on every single poll forever, which
      // is strictly worse and gives no signal beyond "still broken" (found
      // live, 2026-09-02: a device that had just submitted its OWN removal
      // commit got stuck this way receiving a SIBLING's commit afterward,
      // root cause not pinned down under real multi-hour session history
      // despite clean synthetic reproduction attempts).
      try {
        await receiver.receive(entry)
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error)
        console.error('[mimi-vault/decode] commit could not be verified -- this device can no longer sync this Vault room; log out and restore to recover:', detail)
        gaps.push({ kind: 'unverifiable-commit', detail: `seq ${entry.seq}: ${detail}` })
        continue
      }
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
        const detail = error instanceof Error ? error.message : String(error)
        console.warn('[mimi-vault/decode] application entry is permanently undecryptable, skipping:', detail)
        gaps.push({ kind: 'undecryptable-application', detail: `seq ${entry.seq}: ${detail}` })
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
  const unreconstructedCheckpoints: Array<{ manifest: VaultCheckpointManifest; seq: number }> = []
  const claimed = new Set<string>()
  for (const { manifest, seq } of manifests) {
    const values = chunks.get(manifest.transferId)
    let reconstructed = false
    if (values && values.length === manifest.chunkCount) {
      const payload = joinMimiVaultChunks(values.map(value => value.chunk))
      if (equalBytes(sha256Bytes(payload), manifest.payloadHash) && values.every(value => value.chunk.count === manifest.chunkCount && equalBytes(value.chunk.payloadHash, manifest.payloadHash))) {
        checkpoints.push({ transferId: manifest.transferId, payload, finalSequence: Math.max(seq, ...values.map(value => value.seq)), manifest: { ...manifest, payloadHash: manifest.payloadHash.slice() } })
        reconstructed = true
      }
    }
    if (!reconstructed) unreconstructedCheckpoints.push({ manifest, seq })
    claimed.add(manifest.transferId)
  }
  if (unreconstructedCheckpoints.length) {
    // Benign for the device that created this exact checkpoint (its own
    // chunks echo back as `undefined` and never even reach `chunks` above,
    // by design -- decodeMimiVaultBatch has no way to tell that apart from
    // a sibling device genuinely missing the chunk, hence the hedge below).
    // synchronizeMimiVault's recoverSplitCheckpoints retries with a wider
    // pull window right after this; if THAT also comes back empty for the
    // same transferId, the manifest is unreconstructable this round, not a
    // one-off, and turns into an actual `unreconstructed-checkpoint` gap.
    console.warn('[mimi-vault/checkpoint] a manifest arrived without its full chunk set (harmless if this device created it, otherwise a real gap -- retrying with a wider pull):',
      unreconstructedCheckpoints.map(u => `${u.manifest.transferId}@${u.seq}`).join(', '))
  }
  const deliveries: MimiVaultPayload[] = []
  for (const [transferId, values] of chunks) {
    if (claimed.has(transferId)) continue
    deliveries.push({ transferId, payload: joinMimiVaultChunks(values.map(value => value.chunk)), finalSequence: Math.max(...values.map(value => value.seq)) })
  }
  deliveries.sort((left, right) => left.finalSequence - right.finalSequence)
  checkpoints.sort((left, right) => left.finalSequence - right.finalSequence)
  return { deliveries, checkpoints, latestSequence, sawCheckpointManifest: manifests.length > 0, unreconstructedCheckpoints, gaps }
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
