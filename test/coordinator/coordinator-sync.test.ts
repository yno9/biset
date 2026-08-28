import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import type { VaultCoordinatorAckV1, VaultCoordinatorAppendV1, VaultCoordinatorPullV1 } from '../../src/protocol/coordinator.ts'
import type { VaultDeliveryAckOutboxRecord, VaultDeliveryOutboxRecord } from '../../src/vault/store.ts'
import { flushCoordinatorDeliveryOutbox, synchronizeCoordinatorDelivery } from '../../src/vault/coordinator-sync.ts'

const identityId = 'did:webvh:not-visible-to-coordinator.example'
const recipientDeviceId = `${identityId}#device`
const vaultId = `vlt_${'D'.repeat(43)}` as const
const memberId = 'opaque-member'
const secret = new Uint8Array(32).fill(22)

describe('Coordinator local Vault bridge', () => {
  test('keeps identity local while preserving durable outbox, cursor, and ACK ordering', async () => {
    const payload = new Uint8Array([1, 3, 3, 7])
    const payloadHash = sha256Bytes(payload)
    const outbox: VaultDeliveryOutboxRecord[] = [{ identityId, entryId: `sha256:${'E'.repeat(43)}`, payload, payloadHash, createdAt: '2026-08-28T02:00:00.000Z', attempts: 0 }]
    const ackOutbox: VaultDeliveryAckOutboxRecord[] = []
    let cursor = '0'
    let appended: VaultCoordinatorAppendV1 | undefined
    let acknowledged: VaultCoordinatorAckV1 | undefined
    const store = {
      async readDeliveryOutbox() { return outbox.map(value => ({ ...value, payload: value.payload.slice(), payloadHash: value.payloadHash.slice() })) },
      async removeDeliveryOutbox(_identityId: string, entryId: string) { outbox.splice(outbox.findIndex(value => value.entryId === entryId), 1) },
      async noteDeliveryOutboxAttempt() { throw new Error('unexpected append failure') },
      async readDeliveryCursor() { return cursor },
      async readDeliveryAckOutbox() { return ackOutbox.map(value => ({ ...value, ack: { ...value.ack } })) },
      async removeDeliveryAckOutbox(_identityId: string, _deviceId: string, seq: string) { ackOutbox.splice(ackOutbox.findIndex(value => value.seq === seq), 1) },
      async noteDeliveryAckOutboxAttempt() { throw new Error('unexpected ACK failure') },
    }
    const transport = {
      async append(value: VaultCoordinatorAppendV1) { appended = value },
      async pull(_value: VaultCoordinatorPullV1) {
        if (!appended) throw new Error('append must happen first')
        return { kind: 'items' as const, items: [{ version: 1 as const, vaultId, seq: '1', groupEpoch: '1', payload: appended.payload, payloadHash: appended.payloadHash, createdAt: '2026-08-28T02:00:01.000Z', expiresAt: '2026-09-27T02:00:01.000Z' }], nextCursor: '1', retainedFrom: '1', latestSeq: '1' }
      },
      async acknowledge(value: VaultCoordinatorAckV1) { acknowledged = value },
    }
    const signer = { memberId, async sign(bytes: Uint8Array) { return ed25519.sign(bytes, secret) } }
    const now = sequenceClock(['2026-08-28T02:00:02.000Z', '2026-08-28T02:00:03.000Z', '2026-08-28T02:00:04.000Z'])

    expect(await flushCoordinatorDeliveryOutbox(store, transport, signer, identityId, vaultId, '1', 32, now)).toEqual({ appendedEntryIds: [`sha256:${'E'.repeat(43)}`] })
    expect(outbox).toHaveLength(0)
    expect(appended).not.toHaveProperty('identityId')
    expect(appended).toMatchObject({ vaultId, senderMemberId: memberId, groupEpoch: '1' })

    const result = await synchronizeCoordinatorDelivery(store, transport, {
      async ingest(item) {
        expect(item.identityId).toBe(identityId)
        cursor = item.seq
        ackOutbox.push({
          identityId,
          recipientDeviceId,
          seq: item.seq,
          ack: { version: 1, identityId, seq: item.seq, payloadHash: item.payloadHash, recipientDeviceId, checkpointId: 'local-checkpoint', ackedAt: '2026-08-28T02:00:03.500Z', signature: new Uint8Array(64) },
          attempts: 0,
          createdAt: '2026-08-28T02:00:03.500Z',
        })
      },
    }, signer, identityId, recipientDeviceId, vaultId, 32, now)
    expect(result).toEqual({ kind: 'synced', ingestedSequences: ['1'] })
    expect(cursor).toBe('1')
    expect(ackOutbox).toHaveLength(0)
    expect(acknowledged).not.toHaveProperty('identityId')
    expect(acknowledged).toMatchObject({ vaultId, recipientMemberId: memberId, seq: '1' })
  })

  test('retains and reports the concrete append failure for a safe retry', async () => {
    const payload = new Uint8Array([9])
    const entryId = `sha256:${'F'.repeat(43)}`
    let attempts = 0
    const outbox = [{ identityId, entryId, payload, payloadHash: sha256Bytes(payload), createdAt: '2026-08-28T02:00:00.000Z', attempts: 0 }]
    const result = await flushCoordinatorDeliveryOutbox({
      async readDeliveryOutbox() { return outbox },
      async removeDeliveryOutbox() { throw new Error('must remain queued') },
      async noteDeliveryOutboxAttempt() { attempts++ },
    }, {
      async append() { throw new Error('append group epoch is not current') },
    }, {
      memberId, async sign(bytes: Uint8Array) { return ed25519.sign(bytes, secret) },
    }, identityId, vaultId, '1')

    expect(result).toEqual({ appendedEntryIds: [], failedEntryId: entryId, failureReason: 'append group epoch is not current' })
    expect(attempts).toBe(1)
    expect(outbox).toHaveLength(1)
  })
})

function sequenceClock(values: string[]): () => Date {
  let index = 0
  return () => new Date(values[Math.min(index++, values.length - 1)]!)
}
