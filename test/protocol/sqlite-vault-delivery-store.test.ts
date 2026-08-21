import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import { SqliteVaultDeliveryStore } from '../../src/core/mediation/sqlite-vault-delivery-store.ts'
import type { VaultDeliveryAuthorizer } from '../../src/core/mediation/vault-delivery-store.ts'
import type { VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryPullV1 } from '../../src/protocol/vault.ts'

const path = `/tmp/biset-delivery-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const payload = new Uint8Array([1, 2, 3])
const authorizer: VaultDeliveryAuthorizer = {
  async deliveryFloor() { return '1' }, async recipientsAtAppend() { return ['device-a', 'device-b'] }, async verifyAppend() { return true }, async verifyPull() { return true }, async verifyAck() { return true },
}
const append: VaultDeliveryAppendV1 = { version: 1, identityId, appendId: 'event-1', payload, payloadHash: sha256Bytes(payload), senderDeviceId: 'device-a', sentAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([1]) }
const pull: VaultDeliveryPullV1 = { version: 1, identityId, recipientDeviceId: 'device-b', after: '0', requestedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([1]) }
function ack(recipientDeviceId: 'device-a' | 'device-b'): VaultDeliveryAckV1 {
  return { version: 1, identityId, seq: '1', payloadHash: sha256Bytes(payload), recipientDeviceId, checkpointId: `checkpoint-${recipientDeviceId}`, ackedAt: '2026-08-21T01:00:00.000Z', signature: new Uint8Array([1]) }
}

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

describe('SQLite vault delivery store', () => {
  test('survives a core restart while retaining only one pending ciphertext body', async () => {
    const first = SqliteVaultDeliveryStore.open(path, authorizer)
    await first.append(append, new Date('2026-08-21T00:00:00.000Z'))
    first.close()
    const restarted = SqliteVaultDeliveryStore.open(path, authorizer)
    expect(await restarted.pull(pull, new Date('2026-08-21T01:00:00.000Z'))).toMatchObject({ kind: 'items', items: [{ seq: '1', payload }] })
    expect(await restarted.status(identityId)).toMatchObject({ pendingItems: 1, payloadBytes: 3 })
    restarted.close()
  })

  test('does not resurrect a body after every recipient ACKs across a restart', async () => {
    const first = SqliteVaultDeliveryStore.open(path, authorizer)
    await first.append(append, new Date('2026-08-21T00:00:00.000Z'))
    await first.acknowledge(ack('device-a'), new Date('2026-08-21T01:00:00.000Z'))
    await first.acknowledge(ack('device-b'), new Date('2026-08-21T01:00:00.000Z'))
    await expect(first.acknowledge(ack('device-b'), new Date('2026-08-21T01:01:00.000Z'))).resolves.toBeUndefined()
    expect(await first.status(identityId)).toMatchObject({ pendingItems: 0, payloadBytes: 0, retainedFrom: '2' })
    first.close()

    const restarted = SqliteVaultDeliveryStore.open(path, authorizer)
    expect(await restarted.pull({ ...pull, recipientDeviceId: 'device-a' }, new Date('2026-08-21T02:00:00.000Z'))).toMatchObject({ kind: 'restoreRequired', reason: 'delivery-confirmed', retainedFrom: '2', latestSeq: '1' })
    restarted.close()
  })

  test('persists TTL expiry as an explicit restore gap across a restart', async () => {
    const limits = { deliveryTtlMs: 60 * 60 * 1000, maxPayloadBytes: 1024, maxIdentityPayloadBytes: 4096, maxIdentityPendingItems: 4 }
    const first = SqliteVaultDeliveryStore.open(path, authorizer, limits)
    await first.append(append, new Date('2026-08-21T00:00:00.000Z'))
    first.close()

    const restarted = SqliteVaultDeliveryStore.open(path, authorizer, limits)
    expect(await restarted.pull(pull, new Date('2026-08-21T02:00:00.000Z'))).toMatchObject({ kind: 'restoreRequired', reason: 'ttl-expired', retainedFrom: '2', latestSeq: '1' })
    expect(await restarted.status(identityId)).toMatchObject({ pendingItems: 0, payloadBytes: 0 })
    restarted.close()
  })

  test('persists quota eviction as an explicit restore gap across a restart', async () => {
    const limits = { deliveryTtlMs: 24 * 60 * 60 * 1000, maxPayloadBytes: 1024, maxIdentityPayloadBytes: 4096, maxIdentityPendingItems: 1 }
    const first = SqliteVaultDeliveryStore.open(path, authorizer, limits)
    await first.append(append, new Date('2026-08-21T00:00:00.000Z'))
    await first.append({ ...append, appendId: 'event-2', payload: new Uint8Array([4]), payloadHash: sha256Bytes(new Uint8Array([4])) }, new Date('2026-08-21T00:01:00.000Z'))
    expect(await first.status(identityId)).toMatchObject({ pendingItems: 1, retainedFrom: '2', latestSeq: '2' })
    first.close()

    const restarted = SqliteVaultDeliveryStore.open(path, authorizer, limits)
    expect(await restarted.pull(pull, new Date('2026-08-21T02:00:00.000Z'))).toMatchObject({ kind: 'restoreRequired', reason: 'retention-quota', retainedFrom: '2', latestSeq: '2' })
    restarted.close()
  })
})
