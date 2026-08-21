import { describe, expect, test } from 'bun:test'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import { flushVaultDeliveryOutbox, type VaultDeliveryAppendTransport } from '../../src/vault/delivery-outbox.ts'
import type { VaultDeliveryOutboxReader, VaultDeliveryOutboxRecord } from '../../src/vault/store.ts'

const identityId = 'did:web:alice.example'

function entry(entryId: string, payload = new Uint8Array([1])): VaultDeliveryOutboxRecord {
  return { identityId, entryId, payload, payloadHash: sha256Bytes(payload), createdAt: '2026-08-21T00:00:00.000Z', attempts: 0 }
}

class MemoryOutbox implements VaultDeliveryOutboxReader {
  constructor(readonly entries: VaultDeliveryOutboxRecord[]) {}
  async readDeliveryOutbox(): Promise<VaultDeliveryOutboxRecord[]> { return this.entries.map(value => ({ ...value, payload: value.payload.slice(), payloadHash: value.payloadHash.slice() })) }
  async removeDeliveryOutbox(_identityId: string, entryId: string): Promise<void> { this.entries.splice(this.entries.findIndex(entry => entry.entryId === entryId), 1) }
  async noteDeliveryOutboxAttempt(_identityId: string, entryId: string): Promise<void> { this.entries.find(entry => entry.entryId === entryId)!.attempts += 1 }
}

describe('vault delivery outbox', () => {
  test('appends each encrypted payload once and removes it only after the transport accepts it', async () => {
    const outbox = new MemoryOutbox([entry('event-1'), entry('event-2', new Uint8Array([2]))])
    const appended: string[] = []
    const transport: VaultDeliveryAppendTransport = { async append(input) { appended.push(input.appendId) } }
    expect(await flushVaultDeliveryOutbox(outbox, transport, identityId)).toEqual({ appendedEntryIds: ['event-1', 'event-2'] })
    expect(appended).toEqual(['event-1', 'event-2'])
    expect(outbox.entries).toEqual([])
  })

  test('stops at the first failure and retains the causal suffix for retry', async () => {
    const outbox = new MemoryOutbox([entry('event-1'), entry('event-2')])
    const appended: string[] = []
    const transport: VaultDeliveryAppendTransport = { async append(input) {
      appended.push(input.appendId)
      if (input.appendId === 'event-1') throw new Error('offline')
    } }
    expect(await flushVaultDeliveryOutbox(outbox, transport, identityId)).toEqual({ appendedEntryIds: [], failedEntryId: 'event-1' })
    expect(appended).toEqual(['event-1'])
    expect(outbox.entries.map(entry => entry.entryId)).toEqual(['event-1', 'event-2'])
    expect(outbox.entries[0].attempts).toBe(1)
  })
})
