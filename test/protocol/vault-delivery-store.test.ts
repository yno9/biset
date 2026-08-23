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
    verifyAppend: async (input) => input.senderDeviceId === 'device-a' && input.signature.length > 0,
    verifyPull: async (input) => input.recipientDeviceId !== 'device-removed' && input.signature.length > 0,
    verifyAck: async () => true,
  }
}

function pull(deviceId: string, after = '0') {
  return { version: 1 as const, identityId, recipientDeviceId: deviceId, after, requestedAt: '2026-08-21T01:00:00.000Z', signature: new Uint8Array([9]) }
}

function append(overrides: Partial<VaultDeliveryAppendV1> = {}): VaultDeliveryAppendV1 {
  return {
    version: 1,
    identityId,
    appendId: 'event-append-1',
    payload,
    payloadHash: sha256Bytes(payload),
    senderDeviceId: 'device-a',
    sentAt: '2026-08-21T00:00:00.000Z',
    signature: new Uint8Array([9]),
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
    expect((await store.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))).kind).toBe('items')

    await store.acknowledge(ack('device-a'), new Date('2026-08-21T01:00:00.000Z'))
    expect(await store.status(identityId)).toMatchObject({ pendingItems: 1, payloadBytes: 3, retainedFrom: '1' })

    await store.acknowledge(ack('device-b'), new Date('2026-08-21T01:00:00.000Z'))
    expect(await store.status(identityId)).toMatchObject({ pendingItems: 0, payloadBytes: 0, retainedFrom: '2' })
    await expect(store.acknowledge(ack('device-b'), new Date('2026-08-21T01:01:00.000Z'))).resolves.toBeUndefined()
    expect(await store.pull(pull('device-a', '1'), new Date('2026-08-21T01:00:00.000Z')))
      .toMatchObject({ kind: 'items', items: [], nextCursor: '1' })
  })

  test('keeps exactly one payload copy in storage no matter how many devices are recipients', async () => {
    const floors = { 'device-a': '1', 'device-b': '1', 'device-c': '1', 'device-d': '1', 'device-e': '1' }
    const store = new MemoryVaultDeliveryStore(makeAuthorizer(floors))
    await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))

    // payloadBytes reflects ONE stored copy, never payload.length * recipients
    // -- a per-device fanout store would report 5x here.
    expect(await store.status(identityId)).toMatchObject({ payloadBytes: payload.length, pendingItems: 1 })

    // Every recipient independently sees the same single item.
    for (const deviceId of Object.keys(floors)) {
      expect(await store.pull(pull(deviceId), new Date('2026-08-21T01:00:00.000Z')))
        .toMatchObject({ kind: 'items', items: [{ seq: '1', payload }] })
    }

    // Storage still holds exactly one copy after some, but not all, ACK.
    const devices = Object.keys(floors)
    for (const deviceId of devices.slice(0, -1)) {
      await store.acknowledge(ack(deviceId), new Date('2026-08-21T01:00:00.000Z'))
      expect(await store.status(identityId)).toMatchObject({ payloadBytes: payload.length, pendingItems: 1 })
    }
    // The final recipient's ACK frees the single copy.
    await store.acknowledge(ack(devices.at(-1)!), new Date('2026-08-21T01:00:00.000Z'))
    expect(await store.status(identityId)).toMatchObject({ payloadBytes: 0, pendingItems: 0 })
  })

  test('returns restoreRequired instead of an empty success after TTL expiry', async () => {
    // An explicit short TTL, independent of the store's own (30-day
    // production) default -- this test only cares that expiry produces
    // restoreRequired, not what the default retention window actually is.
    const store = new MemoryVaultDeliveryStore(makeAuthorizer(), { maxPayloadBytes: 1024, maxIdentityPayloadBytes: 4096, maxIdentityPendingItems: 4, deliveryTtlMs: 24 * 60 * 60 * 1000 })
    await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    expect(await store.pull(pull('device-b'), new Date('2026-08-23T00:00:00.000Z')))
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
    expect(await store.pull(pull('device-new'), new Date('2026-08-21T01:00:00.000Z')))
      .toMatchObject({ kind: 'restoreRequired', reason: 'new-device', retainedFrom: '1', latestSeq: '1' })
  })

  test('takes the append-time recipient snapshot from the core authorizer, never the append caller', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer({ 'device-a': '1', 'device-b': '1', 'device-new': '2' }))
    await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    expect(await store.pull(pull('device-b'), new Date('2026-08-21T01:00:00.000Z'))).toMatchObject({ kind: 'items', items: [{ seq: '1' }] })
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

  test('rejects an unauthorised sender even if its append ID and payload hash are valid', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer())
    await expect(store.append({ ...append(), senderDeviceId: 'device-removed' })).rejects.toThrow('not authorised')
  })

  test('rejects a pull whose signed device is no longer authorised', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer())
    await store.append(append())
    await expect(store.pull(pull('device-removed'))).rejects.toThrow('not authorised')
  })

  test('rejects an ACK with a different payload hash', async () => {
    const store = new MemoryVaultDeliveryStore(makeAuthorizer())
    await store.append(append(), new Date('2026-08-21T00:00:00.000Z'))
    await expect(store.acknowledge(ack('device-a', { payloadHash: new Uint8Array([8]) }))).rejects.toThrow('does not match')
  })
})
