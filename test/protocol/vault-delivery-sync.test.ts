import { describe, expect, test } from 'bun:test'
import { synchronizeVaultDelivery } from '../../src/vault/delivery-sync.ts'
import type { VaultDeliveryAckOutboxReader, VaultDeliveryAckOutboxRecord, VaultDeliveryCursorReader } from '../../src/vault/store.ts'
import type { DeliveryPullResult, VaultDeliveryItemV1 } from '../../src/shared/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const deviceId = 'device-b'
const signer = { deviceId, async sign() { return new Uint8Array([7]) } }

function item(seq: string): VaultDeliveryItemV1 {
  return { version: 1, identityId, seq, payload: new Uint8Array([Number(seq)]), payloadHash: new Uint8Array([Number(seq)]), createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z' }
}

function ack(seq: string): VaultDeliveryAckOutboxRecord {
  return { identityId, recipientDeviceId: deviceId, seq, attempts: 0, createdAt: '2026-08-21T00:00:00.000Z', ack: { version: 1, identityId, seq, payloadHash: new Uint8Array([Number(seq)]), recipientDeviceId: deviceId, checkpointId: `checkpoint-${seq}`, ackedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([1]) } }
}

class MemoryDeliveryState implements VaultDeliveryCursorReader, VaultDeliveryAckOutboxReader {
  cursor = '1'
  constructor(readonly acks: VaultDeliveryAckOutboxRecord[]) {}
  async readDeliveryCursor() { return this.cursor }
  async readDeliveryAckOutbox() { return this.acks.map(value => ({ ...value, ack: { ...value.ack } })) }
  async removeDeliveryAckOutbox(_identity: string, _device: string, seq: string) { this.acks.splice(this.acks.findIndex(value => value.seq === seq), 1) }
  async noteDeliveryAckOutboxAttempt(_identity: string, _device: string, seq: string) { this.acks.find(value => value.seq === seq)!.attempts += 1 }
}

describe('vault delivery synchronisation', () => {
  test('flushes durable ACKs around a cursor-based pull and ingests items in sequence', async () => {
    const state = new MemoryDeliveryState([ack('1')])
    const pulls: string[] = []
    const acknowledged: string[] = []
    const ingested: string[] = []
    const output = await synchronizeVaultDelivery(state, {
      async pull(input): Promise<DeliveryPullResult> { pulls.push(input.after); return { kind: 'items', items: [item('2')], nextCursor: '2', retainedFrom: '2', latestSeq: '2' } },
      async acknowledge(value) { acknowledged.push(value.seq) },
    }, {
      async ingest(value) { ingested.push(value.seq); state.cursor = value.seq; state.acks.push(ack(value.seq)) },
    }, signer, identityId, deviceId)
    expect(output).toEqual({ kind: 'synced', ingestedSequences: ['2'] })
    expect(pulls).toEqual(['1'])
    expect(ingested).toEqual(['2'])
    expect(acknowledged).toEqual(['1', '2'])
    expect(state.acks).toEqual([])
  })

  test('surfaces restoreRequired without treating the gap as an empty successful sync', async () => {
    const state = new MemoryDeliveryState([])
    let ingested = false
    const output = await synchronizeVaultDelivery(state, {
      async pull(): Promise<DeliveryPullResult> { return { kind: 'restoreRequired', requestedCursor: '1', retainedFrom: '9', latestSeq: '12', reason: 'ttl-expired' } },
      async acknowledge() { throw new Error('no ACK') },
    }, {
      async ingest() { ingested = true },
    }, signer, identityId, deviceId)
    expect(output).toEqual({ kind: 'restoreRequired', result: { kind: 'restoreRequired', requestedCursor: '1', retainedFrom: '9', latestSeq: '12', reason: 'ttl-expired' } })
    expect(ingested).toBe(false)
  })

  test('retains a failed ACK for a later retry while still reporting a completed local ingest', async () => {
    const state = new MemoryDeliveryState([])
    const output = await synchronizeVaultDelivery(state, {
      async pull(): Promise<DeliveryPullResult> { return { kind: 'items', items: [item('2')], nextCursor: '2', retainedFrom: '2', latestSeq: '2' } },
      async acknowledge() { throw new Error('offline') },
    }, {
      async ingest(value) { state.cursor = value.seq; state.acks.push(ack(value.seq)) },
    }, signer, identityId, deviceId)
    expect(output).toEqual({ kind: 'synced', ingestedSequences: ['2'], pendingAckSequence: '2' })
    expect(state.acks[0].attempts).toBe(1)
  })
})
