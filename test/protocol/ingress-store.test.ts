import { describe, expect, test } from 'bun:test'
import { MemoryIngressStore, type IngressAuthorizer } from '../../src/core/mediation/ingress-store.ts'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../../src/protocol/ingress.ts'

const authorizer: IngressAuthorizer = {
  verifyPull: async (pull) => ['device-a', 'device-b', 'device-new'].includes(pull.recipientDeviceId),
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
    protectedPayloadHash: sha256Bytes(new Uint8Array([2, 3])),
    ...overrides,
  }
}

function ack(overrides: Partial<IngressAckV1> = {}): IngressAckV1 {
  return {
    version: 1,
    ingressId: 'ingress-1',
    protectedPayloadHash: sha256Bytes(new Uint8Array([2, 3])),
    recipientDeviceId: 'device-a',
    vaultEventId: 'event-1',
    checkpointId: 'checkpoint-1',
    ackedAt: '2026-08-21T01:00:00.000Z',
    signature: new Uint8Array([9]),
    ...overrides,
  }
}

function pull(recipientDeviceId: string): IngressPullV1 {
  return { version: 1, identityId: 'did:webvh:example:alice', recipientDeviceId, requestedAt: '2026-08-21T01:00:00.000Z', signature: new Uint8Array([8]) }
}

describe('MemoryIngressStore', () => {
  test('deletes a payload after one authorised durable ACK', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())

    expect((await store.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))).length).toBe(1)
    await store.acknowledge(ack(), new Date('2026-08-21T01:00:00.000Z'))

    expect(await store.status('ingress-1')).toEqual({
      ingressId: 'ingress-1',
      identityId: 'did:webvh:example:alice',
      status: 'vault-ingested',
      expiresAt: '2026-08-22T00:00:00.000Z',
      payloadRetained: false,
    })
    expect((await store.pull(pull('device-b'), new Date('2026-08-21T02:00:00.000Z'))).length).toBe(0)
  })

  test('re-ACKing an already-ingested envelope is rejected, not silently accepted again', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())
    await store.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))
    await store.acknowledge(ack(), new Date('2026-08-21T01:00:00.000Z'))
    await expect(store.acknowledge(ack(), new Date('2026-08-21T01:01:00.000Z'))).rejects.toThrow('already vault-ingested')
  })

  test('the same payload hash under a DIFFERENT ingressId is a distinct entry, not deduped', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())
    await store.offer(envelope({ ingressId: 'ingress-2' }))
    expect(await store.status('ingress-1')).toMatchObject({ status: 'pending' })
    expect(await store.status('ingress-2')).toMatchObject({ status: 'pending' })
    expect((await store.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))).map(value => value.ingressId).sort())
      .toEqual(['ingress-1', 'ingress-2'])
  })

  test('does not expose an ingress to a device outside its frozen snapshot', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())
    expect(await store.pull(pull('device-new'), new Date('2026-08-21T01:00:00.000Z'))).toEqual([])
  })

  test('does not expose a snapshot ingress to a device removed after offer', async () => {
    const store = new MemoryIngressStore({
      verifyPull: async (value) => value.recipientDeviceId === 'device-a',
      verify: async () => true,
    })
    await store.offer(envelope())
    await expect(store.pull(pull('device-b'), new Date('2026-08-21T01:00:00.000Z'))).rejects.toThrow('not authorised')
  })

  test('expires the payload but retains only a status tombstone', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())
    await store.expire(new Date('2026-08-23T00:00:00.000Z'))
    expect(await store.status('ingress-1')).toMatchObject({ status: 'expired', payloadRetained: false })
    await expect(store.acknowledge(ack(), new Date('2026-08-23T00:00:00.000Z'))).rejects.toThrow('already expired')
  })

  test('a concurrent expire() sweep during an in-flight ACK does not resurrect the entry as vault-ingested', async () => {
    // authorizer.verify deliberately suspends (a real DID/roster check can
    // genuinely take a tick) so a concurrent expire() has a real window to
    // run while this ACK is mid-flight.
    let releaseVerify: (() => void) | undefined
    const gatedAuthorizer: IngressAuthorizer = {
      verifyPull: async () => true,
      verify: async () => { await new Promise<void>(resolve => { releaseVerify = resolve }); return true },
    }
    const store = new MemoryIngressStore(gatedAuthorizer)
    await store.offer(envelope({ expiresAt: '2026-08-21T00:30:00.000Z' }))
    await store.pull(pull('device-a'), new Date('2026-08-21T00:00:00.000Z'))

    const ackPromise = store.acknowledge(ack(), new Date('2026-08-21T00:00:00.000Z'))
    for (let i = 0; i < 4; i++) await Promise.resolve()

    // While the ACK is suspended, a concurrent operation sweeps this entry
    // past its expiry.
    await store.expire(new Date('2026-08-21T01:00:00.000Z'))
    expect(await store.status('ingress-1')).toMatchObject({ status: 'expired' })

    // Resume the ACK. It must see the FRESH (expired) status, not the stale
    // 'pending' snapshot checked before suspending.
    releaseVerify!()
    await expect(ackPromise).rejects.toThrow('already expired')
    expect(await store.status('ingress-1')).toMatchObject({ status: 'expired' })
  })

  test('rejects a forged ACK hash before authorisation is accepted', async () => {
    const store = new MemoryIngressStore(authorizer)
    await store.offer(envelope())
    await store.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))
    await expect(store.acknowledge(ack({ protectedPayloadHash: new Uint8Array([8]) }), new Date('2026-08-21T01:00:00.000Z'))).rejects.toThrow('does not match')
  })

  test('leases a body to one endpoint and releases it after the bounded claim expires', async () => {
    const store = new MemoryIngressStore(authorizer, { maxPayloadBytes: 100, maxIdentityPayloadBytes: 100, maxIdentityPendingItems: 10, claimLeaseMs: 1_000 })
    await store.offer(envelope())
    expect(await store.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))).toHaveLength(1)
    expect(await store.pull(pull('device-b'), new Date('2026-08-21T01:00:00.500Z'))).toEqual([])
    await expect(store.acknowledge(ack({ recipientDeviceId: 'device-b' }), new Date('2026-08-21T01:00:00.500Z'))).rejects.toThrow('active ingress claim')
    expect(await store.pull(pull('device-b'), new Date('2026-08-21T01:00:01.000Z'))).toHaveLength(1)
  })

  test('rejects an adapter offer whose declared body hash is not the body hash', async () => {
    const store = new MemoryIngressStore(authorizer)
    await expect(store.offer(envelope({ protectedPayloadHash: new Uint8Array([8]) }))).rejects.toThrow('protectedPayloadHash does not match')
  })
})
