import { expect, test } from 'bun:test'
import { sha256Bytes } from '../src/protocol/canonical.ts'
import { decodeMimiVaultBatch, flushMimiVaultOutbox, sendMimiVaultCheckpoint } from '../src/vault/mimi-vault-sync.ts'
import { encodeMimiVaultChunk, splitMimiVaultPayload } from '../src/vault/mimi-vault-chunks.ts'

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
