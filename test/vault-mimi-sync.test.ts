import { expect, test } from 'bun:test'
import { sha256Bytes } from '../src/protocol/canonical.ts'
import { decodeMimiVaultBatch, flushMimiVaultOutbox, pullMimiVaultPages, sendMimiVaultCheckpoint, synchronizeMimiVault } from '../src/vault/mimi-vault-sync.ts'
import { encodeMimiVaultChunk, splitMimiVaultPayload } from '../src/vault/mimi-vault-chunks.ts'
import type { MimiDeliveryEntry } from '../src/mimi/protocol-types.ts'

test('MIMI Vault outbox uses stable per-chunk delivery IDs and retains failed work', async () => {
  const payload = new Uint8Array([1, 2, 3]); const removed: string[] = []; const attempts: string[] = []; const sent: string[] = []
  const outbox = {
    async readDeliveryOutbox() { return [{ identityId: 'did:example:me', entryId: 'evt-1' as never, payload, payloadHash: sha256Bytes(payload) }] },
    async removeDeliveryOutbox(_identity: string, entry: string) { removed.push(entry) }, async noteDeliveryOutboxAttempt(_identity: string, entry: string) { attempts.push(entry) },
  }
  const result = await flushMimiVaultOutbox(outbox, { async sendApplication(_chunk, deliveryId) { sent.push(deliveryId) }, async sendCheckpoint() {} }, 'did:example:me' as never)
  expect(result.appendedEntryIds).toEqual(['evt-1']); expect(removed).toEqual(['evt-1']); expect(attempts).toEqual([]); expect(sent[0]).toMatch(/^[A-Za-z0-9_-]{43}$/)
})

test('MIMI Vault receive path separates checkpoint chunks from ordinary Vault payloads', async () => {
  const ordinary = splitMimiVaultPayload(new Uint8Array([7, 8]), 'A'.repeat(24))[0]!; const checkpoint = splitMimiVaultPayload(new Uint8Array([9, 10]), 'B'.repeat(24))[0]!
  const decoded = await decodeMimiVaultBatch([
    { seq: 1, kind: 'application', payload: encodeMimiVaultChunk(ordinary), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z' },
    { seq: 2, kind: 'application', payload: encodeMimiVaultChunk(checkpoint), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z' },
    { seq: 3, kind: 'vaultCheckpoint', payload: new Uint8Array(), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z', vaultCheckpoint: { coveredSeq: 1, transferId: checkpoint.transferId, chunkCount: 1, payloadHash: checkpoint.payloadHash } },
  ], { async receive(entry) { return entry.kind === 'application' ? entry.payload : undefined } })
  expect(decoded.deliveries.map(value => value.payload)).toEqual([ordinary.payload]); expect(decoded.checkpoints.map(value => value.payload)).toEqual([checkpoint.payload])
})

test('checkpoint manifest is sent after its encrypted chunks', async () => {
  const order: string[] = []
  const manifest = await sendMimiVaultCheckpoint(new Uint8Array([4]), 2, { async sendApplication(_payload, deliveryId) { order.push(deliveryId) }, async sendCheckpoint(value) { order.push(`checkpoint:${value.transferId}`) } })
  expect(order).toEqual([expect.any(String), `checkpoint:${manifest.transferId}`])
})

test('synchronizeMimiVault recovers a checkpoint whose chunk was pulled in an earlier round than its manifest', async () => {
  // Reproduces the found-live bug (2026-09-02): sendMimiVaultCheckpoint
  // submits the chunk, then the manifest, as two separate deliveries. If
  // this device's pull window starts strictly AFTER the chunk's seq but
  // AT/BEFORE the manifest's, the manifest arrives alone -- before this
  // fix, decodeMimiVaultBatch would silently drop it forever (the cursor
  // advances past it regardless), leaving the Vault permanently stuck with
  // no error at all.
  const checkpointChunk = splitMimiVaultPayload(new Uint8Array([9, 10, 11]), 'C'.repeat(24))[0]!
  const manifestEntry: MimiDeliveryEntry = {
    seq: 11, kind: 'vaultCheckpoint', payload: new Uint8Array(), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z',
    vaultCheckpoint: { coveredSeq: 10, transferId: checkpointChunk.transferId, chunkCount: 1, payloadHash: checkpointChunk.payloadHash },
  }
  const chunkEntry: MimiDeliveryEntry = { seq: 5, kind: 'application', payload: encodeMimiVaultChunk(checkpointChunk), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z' }

  // This device's own pull starts at afterSeq=10 -- past the chunk (seq 5,
  // already consumed in some earlier round this test doesn't model), right
  // at the manifest (seq 11).
  const pullCalls: number[] = []
  const pull = async (request: { afterSeq: number }) => {
    pullCalls.push(request.afterSeq)
    if (request.afterSeq === 10) return [manifestEntry]
    // The retry's wider pull, from well before seq 5 -- a real hub would
    // return everything since then, chunk and manifest both.
    return [chunkEntry, manifestEntry]
  }
  const restored: unknown[] = []
  const result = await synchronizeMimiVault({
    pull, signPull: async () => new Uint8Array(64),
    pullRequest: { version: 1, roomId: 'mimi://self.example/r/vault-test', requester: { kind: 'visible', user: 'did:example:me', client: 'client', credential: new Uint8Array([1]), signaturePublicKey: new Uint8Array(32) }, requestedAt: '2026-09-02T00:00:00.000Z' },
    receiver: { async receive(entry) { return entry.kind === 'application' ? entry.payload : undefined } },
    outbox: { async readDeliveryOutbox() { return [] } },
    sender: { async sendApplication() {}, async sendCheckpoint() {} },
    identityId: 'did:example:me' as never,
    async ingest() {},
    async restoreCheckpoint(checkpoint) { restored.push(checkpoint) },
    afterSeq: 10,
  })
  expect(pullCalls).toEqual([10, 0]) // the original pull, then the retry from afterSeq=0 (5 - margin, clamped)
  expect(restored).toHaveLength(1)
  expect((restored[0] as { payload: Uint8Array }).payload).toEqual(checkpointChunk.payload)
  expect(result.checkpoints).toHaveLength(1)
})

test('synchronizeMimiVault reports an undecryptable application entry as a gap instead of only logging it', async () => {
  // The `gaps` report (PLAN-SIMPIFY.md direction B) is what main.ts's
  // checkpoint auto-recreate gate now checks before publishing -- a device
  // whose own batch had an unrecoverable loss must not confidently claim
  // its local state is a complete "latest" for siblings to restore from.
  const good = splitMimiVaultPayload(new Uint8Array([1]), 'D'.repeat(24))[0]!
  const entries: MimiDeliveryEntry[] = [
    { seq: 1, kind: 'application', payload: encodeMimiVaultChunk(good), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z' },
    { seq: 2, kind: 'application', payload: new Uint8Array([9, 9, 9]), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z' },
  ]
  const ingested: unknown[] = []
  const result = await synchronizeMimiVault({
    pull: async () => entries, signPull: async () => new Uint8Array(64),
    pullRequest: { version: 1, roomId: 'mimi://self.example/r/vault-test', requester: { kind: 'visible', user: 'did:example:me', client: 'client', credential: new Uint8Array([1]), signaturePublicKey: new Uint8Array(32) }, requestedAt: '2026-09-02T00:00:00.000Z' },
    receiver: { async receive(entry) { if (entry.seq === 2) throw new Error('Desired gen in the past'); return entry.payload } },
    outbox: { async readDeliveryOutbox() { return [] } },
    sender: { async sendApplication() {}, async sendCheckpoint() {} },
    identityId: 'did:example:me' as never,
    async ingest(payload) { ingested.push(payload) },
  })
  expect(ingested).toHaveLength(1) // the one good entry still applies despite the other's loss
  expect(result.gaps).toEqual([{ kind: 'undecryptable-application', detail: expect.stringContaining('Desired gen in the past') }])
})

test('synchronizeMimiVault never throws when the outbox flush fails, reporting it as a gap instead', async () => {
  const result = await synchronizeMimiVault({
    pull: async () => [], signPull: async () => new Uint8Array(64),
    pullRequest: { version: 1, roomId: 'mimi://self.example/r/vault-test', requester: { kind: 'visible', user: 'did:example:me', client: 'client', credential: new Uint8Array([1]), signaturePublicKey: new Uint8Array(32) }, requestedAt: '2026-09-02T00:00:00.000Z' },
    receiver: { async receive() { return undefined } },
    outbox: {
      async readDeliveryOutbox() { return [{ identityId: 'did:example:me', entryId: 'evt-bad' as never, payload: new Uint8Array(), payloadHash: new Uint8Array(32) }] },
      async removeDeliveryOutbox() {}, async noteDeliveryOutboxAttempt() {},
    },
    sender: { async sendApplication() {}, async sendCheckpoint() {} },
    identityId: 'did:example:me' as never,
    async ingest() {},
  })
  expect(result.gaps).toEqual([{ kind: 'outbox-flush-failed', detail: expect.any(String) }])
})

test('MIMI Vault pulls all 32-item pages before chunk reconstruction', async () => {
  const first = Array.from({ length: 32 }, (_, index) => ({ seq: index + 1, kind: 'application' as const, payload: new Uint8Array([index]), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z' }))
  const second = [{ seq: 33, kind: 'application' as const, payload: new Uint8Array([33]), epoch: '1', acceptedAt: '2026-09-02T00:00:00.000Z' }]
  const result = await pullMimiVaultPages(async request => request.afterSeq === 0 ? first : second, async () => new Uint8Array(64), {
    version: 1, roomId: 'mimi://self.example/r/vault-test', requester: { kind: 'visible', user: 'did:example:me', client: 'client', credential: new Uint8Array([1]), signaturePublicKey: new Uint8Array(32) }, requestedAt: '2026-09-02T00:00:00.000Z',
  })
  expect(result).toHaveLength(33)
})
