import { describe, expect, test } from 'bun:test'
import { MemoryRestoreControlStore, type RestoreControlAuthorizer } from '../../src/core/mediation/restore-control-store.ts'
import type { RestoreCancelV1, RestoreOfferV1, RestoreRequestV1 } from '../../src/protocol/vault.ts'

const authorizer: RestoreControlAuthorizer = {
  async isTrustedDevice(_identityId, deviceId) {
    return ['device-a', 'device-b', 'device-c'].includes(deviceId)
  },
  async verifyRequest(request) {
    return request.signature[0] === 1
  },
  async verifyOffer(offer) {
    return offer.signature[0] === 2
  },
  async verifyCancel(cancel) {
    return cancel.signature[0] === 3
  },
}

function request(overrides: Partial<RestoreRequestV1> = {}): RestoreRequestV1 {
  return {
    version: 1,
    requestId: 'restore-1',
    identityId: 'did:web:alice.example',
    requesterDeviceId: 'device-c',
    reason: 'ttl-expired',
    knownManifestRoot: 'root-c',
    requestedAt: '2026-08-21T00:00:00.000Z',
    expiresAt: '2026-08-21T00:15:00.000Z',
    signature: new Uint8Array([1]),
    ...overrides,
  }
}

function offer(overrides: Partial<RestoreOfferV1> = {}): RestoreOfferV1 {
  return {
    version: 1,
    requestId: 'restore-1',
    identityId: 'did:web:alice.example',
    requesterDeviceId: 'device-c',
    responderDeviceId: 'device-a',
    manifestRoot: 'root-a',
    offeredAt: '2026-08-21T00:01:00.000Z',
    expiresAt: '2026-08-21T00:10:00.000Z',
    signature: new Uint8Array([2]),
    ...overrides,
  }
}

describe('restore control store', () => {
  test('relays only small signed restore control between trusted peer devices', async () => {
    const store = new MemoryRestoreControlStore(authorizer)
    const now = new Date('2026-08-21T00:00:00.000Z')
    await store.request(request(), now)

    expect(await store.pullRequests('did:web:alice.example', 'device-a', now)).toEqual([request()])
    expect(await store.pullRequests('did:web:alice.example', 'device-c', now)).toEqual([])

    await store.offer(offer(), now)
    expect(await store.pullOffers('did:web:alice.example', 'device-c', now)).toEqual([offer()])
    await expect(store.pullRequests('did:web:alice.example', 'not-a-device', now)).rejects.toThrow('not trusted')
  })

  test('expires requests and rejects an offer after its request has disappeared', async () => {
    const store = new MemoryRestoreControlStore(authorizer)
    await store.request(request({ expiresAt: '2026-08-21T00:01:00.000Z' }), new Date('2026-08-21T00:00:00.000Z'))
    await store.expire(new Date('2026-08-21T00:01:00.000Z'))
    expect(await store.pullRequests('did:web:alice.example', 'device-a')).toEqual([])
    await expect(store.offer(offer(), new Date('2026-08-21T00:01:00.000Z'))).rejects.toThrow('absent or no longer active')
  })

  test('lets only the requester cancel an active restore request', async () => {
    const store = new MemoryRestoreControlStore(authorizer)
    const now = new Date('2026-08-21T00:00:00.000Z')
    await store.request(request(), now)
    const cancel: RestoreCancelV1 = {
      version: 1,
      requestId: 'restore-1',
      identityId: 'did:web:alice.example',
      requesterDeviceId: 'device-c',
      cancelledAt: '2026-08-21T00:02:00.000Z',
      signature: new Uint8Array([3]),
    }
    await store.cancel(cancel, now)
    expect(await store.pullRequests('did:web:alice.example', 'device-a', now)).toEqual([])
  })
})
