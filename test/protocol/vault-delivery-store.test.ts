import { describe, expect, test } from 'bun:test'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import {
  MemoryVaultDeliveryStore,
  type VaultDeliveryAuthorizer,
} from '../../src/core/mediation/vault-delivery-store.ts'
import type { VaultDeliveryAckV1, VaultDeliveryAppendV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:webvh:example:alice'
const payload = new Uint8Array([1, 2, 3])

function makeAuthorizer(floors: Record<string, string> = { 'device-a': '1', 'device-b': '1' }): VaultDeliveryAuthorizer {
  return {
    deliveryFloor: async (_identityId, deviceId) => floors[deviceId],
    recipientsAtAppend: async () => Object.entries(floors).filter(([, floor]) => floor === '1').map(([deviceId]) => deviceId),
    verifyAck: async () => true,
  }
}

function append(overrides: Partial<VaultDeliveryAppendV1> = {}): VaultDeliveryAppendV1 {
  return {
    version: 1,
    identityId,
    appendId: 'event-append-1',
    payload,
    payloadHash: sha256Bytes(payload),
    ...overrides,
  }
}

function ack(deviceId: string, overrides: Partial<VaultDeliveryAckV1> = {}): VaultDeliveryAckV1 {
  return {
    version: 1,
    identityId,
    seq: '1',
    payloadHash: sha256Bytes(payload),
    recipientDeviceId: deviceId,
    checkpointId: `checkpoint-${deviceId}`,
    ackedAt: '2026-08-21T01:00:00.000Z',
    signature: new Uint8Array([9]),
    ...overrides,
  }
}

describe('MemoryVaultDeliveryStore', () => {
  test('retains one payload until every append-time recipient durably ACKs it', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer())
    const item = await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    expect(item.seq).toBe('1')
    expect((await store.pull(identityId, 'device-a', '0', new Date('2026-08-21T01:00:00.000Z'))).kind).toBe('items')

    await store.acknowledge(ack('device-a'), new Date('2026-08-21T01:00:00.000Z'))
    expect(await store.status(identityId)).toMatchObject({ pendingItems: 1, payloadBytes: 3, retainedFrom: '1' })

    await store.acknowledge(ack('device-b'), new Date('2026-08-21T01:00:00.000Z'))
    expect(await store.status(identityId)).toMatchObject({ pendingItems: 0, payloadBytes: 0, retainedFrom: '2' })
    expect(await store.pull(identityId, 'device-a', '1', new Date('2026-08-21T01:00:00.000Z')))
      .toMatchObject({ kind: 'items', items: [], nextCursor: '1' })
  })

  test('returns restoreRequired instead of an empty success after TTL expiry', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer())
    await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    expect(await store.pull(identityId, 'device-b', '0', new Date('2026-08-23T00:00:00.000Z')))
      .toEqual({
        kind: 'restoreRequired',
        requestedCursor: '0',
        retainedFrom: '2',
        latestSeq: '1',
        reason: 'ttl-expired',
      })
  })

  test('makes a later-joined device restore prior history rather than adding it to an old snapshot', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer({ 'device-a': '1', 'device-b': '1', 'device-new': '2' }))
    await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    expect(await store.pull(identityId, 'device-new', '0', new Date('2026-08-21T01:00:00.000Z')))
      .toMatchObject({ kind: 'restoreRequired', reason: 'new-device', retainedFrom: '1', latestSeq: '1' })
  })

  test('takes the append-time recipient snapshot from the core authorizer, never the append caller', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer({ 'device-a': '1', 'device-b': '1', 'device-new': '2' }))
    await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    expect(await store.pull(identityId, 'device-b', '0', new Date('2026-08-21T01:00:00.000Z'))).toMatchObject({ kind: 'items', items: [{ seq: '1' }] })
    await expect(store.append({ ...append(), recipientsAtAppend: ['device-a'] } as VaultDeliveryAppendV1)).rejects.toThrow('unknown field recipientsAtAppend')
    await expect(store.append({ ...append(), expiresAt: '2099-01-01T00:00:00.000Z' } as VaultDeliveryAppendV1)).rejects.toThrow('unknown field expiresAt')
  })

  test('uses the append ID to make an uncertain outbox retry idempotent', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer())
    const first = await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    const retry = await store.append(append(), new Date('2026-08-21T01:00:00.000Z'))
    expect(retry).toEqual(first)
    expect(await store.status(identityId)).toMatchObject({ latestSeq: '1', pendingItems: 1 })
    await expect(store.append({ ...append(), payload: new Uint8Array([4]), payloadHash: sha256Bytes(new Uint8Array([4]) ) })).rejects.toThrow('different payload')
  })

  test('rejects an ACK with a different payload hash', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer())
    await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    await expect(store.acknowledge(ack('device-a', { payloadHash: new Uint8Array([8]) }))).rejects.toThrow('does not match')
  })
})
