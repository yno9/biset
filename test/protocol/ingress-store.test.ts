import { describe, expect, test } from 'bun:test'
import { MemoryIngressStore, type IngressAckAuthorizer } from '../../src/core/mediation/ingress-store.ts'
import type { IngressAckV1, IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'

const authorizer: IngressAckAuthorizer = {
  isTrustedDevice: async (_identityId, deviceId) => ['device-a', 'device-b'].includes(deviceId),
  verify: async () => true,
}

function envelope(overrides: Partial<IngressEnvelopeV1> = {}): IngressEnvelopeV1 {
  return {
    version: 1,
    ingressId: 'ingress-1',
    protocol: 'mail',
    recipientIdentityId: 'did:webvh:example:alice',
    recipientDeviceSnapshot: ['device-a', 'device-b'],
    createdAt: '2026-08-21T00:00:00.000Z',
    expiresAt: '2026-08-22T00:00:00.000Z',
    transportMetadata: {},
    sourceEvidence: new Uint8Array([1]),
    protectedPayload: new Uint8Array([2, 3]),
    protectedPayloadHash: new Uint8Array([4, 5]),
    ...overrides,
  }
}

function ack(overrides: Partial<IngressAckV1> = {}): IngressAckV1 {
  return {
    version: 1,
    ingressId: 'ingress-1',
    protectedPayloadHash: new Uint8Array([4, 5]),
    recipientDeviceId: 'device-a',
    vaultEventId: 'event-1',
    checkpointId: 'checkpoint-1',
    ackedAt: '2026-08-21T01:00:00.000Z',
    signature: new Uint8Array([9]),
    ...overrides,
  }
}

describe('MemoryIngressStore', () => {
  test('deletes a payload after one authorised durable ACK', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())

    expect((await store.pull('did:webvh:example:alice', 'device-a', new Date('2026-08-21T01:00:00.000Z'))).length).toBe(1)
    await store.acknowledge(ack(), new Date('2026-08-21T01:00:00.000Z'))

    expect(await store.status('ingress-1')).toEqual({
      ingressId: 'ingress-1',
      identityId: 'did:webvh:example:alice',
      status: 'vault-ingested',
      expiresAt: '2026-08-22T00:00:00.000Z',
      payloadRetained: false,
    })
    expect((await store.pull('did:webvh:example:alice', 'device-b', new Date('2026-08-21T02:00:00.000Z'))).length).toBe(0)
  })

  test('does not expose an ingress to a device outside its frozen snapshot', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())
    expect(await store.pull('did:webvh:example:alice', 'device-new', new Date('2026-08-21T01:00:00.000Z'))).toEqual([])
  })

  test('does not expose a snapshot ingress to a device removed after offer', async () => {
    const store = new MemoryIngressStore({
      isTrustedDevice: async (_identityId, deviceId) => deviceId === 'device-a',
      verify: async () => true,
    })
    await store.offer(envelope())
    expect(await store.pull('did:webvh:example:alice', 'device-b', new Date('2026-08-21T01:00:00.000Z'))).toEqual([])
  })

  test('expires the payload but retains only a status tombstone', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())
    await store.expire(new Date('2026-08-23T00:00:00.000Z'))
    expect(await store.status('ingress-1')).toMatchObject({ status: 'expired', payloadRetained: false })
    await expect(store.acknowledge(ack(), new Date('2026-08-23T00:00:00.000Z'))).rejects.toThrow('already expired')
  })

  test('rejects a forged ACK hash before authorisation is accepted', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())
    await expect(store.acknowledge(ack({ protectedPayloadHash: new Uint8Array([8]) }))).rejects.toThrow('does not match')
  })
})
