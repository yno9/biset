import { describe, expect, test } from 'bun:test'
import { MemoryRestoreControlStore, type RestoreControlAuthorizer } from '../../src/core/mediation/restore-control-store.ts'
import type { RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1 } from '../../src/protocol/vault.ts'

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
  async verifyPull(pull) {
    return pull.signature[0] === 4
  },
}

function pull(deviceId: string, kind: RestoreControlPullV1['kind']): RestoreControlPullV1 {
  return { version: 1, identityId: 'did:web:alice.example', deviceId, kind, requestedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([4]) }
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

    expect(await store.pullRequests(pull('device-a', 'requests'), now)).toEqual([request()])
    expect(await store.pullRequests(pull('device-c', 'requests'), now)).toEqual([])

    await store.offer(offer(), now)
    await expect(store.offer(offer({ responderDeviceId: 'device-b', expiresAt: '2026-08-21T00:16:00.000Z' }), now)).rejects.toThrow('cannot outlive')
    expect(await store.pullOffers(pull('device-c', 'offers'), now)).toEqual([offer()])
    await expect(store.pullRequests(pull('not-a-device', 'requests'), now)).rejects.toThrow('not trusted')
    await expect(store.pullRequests(pull('device-a', 'offers'), now)).rejects.toThrow('kind must be requests')
  })

  test('resubmitting an identical offer is a silent no-op; resubmitting a conflicting one is rejected', async () => {
    const store = new MemoryRestoreControlStore(authorizer)
    const now = new Date('2026-08-21T00:00:00.000Z')
    await store.request(request(), now)
    await store.offer(offer(), now)

    // The exact same offer again -- a client retry after a lost response
    // must be a no-op, not an error and not a second entry.
    await expect(store.offer(offer(), now)).resolves.toBeUndefined()
    expect(await store.pullOffers(pull('device-c', 'offers'), now)).toEqual([offer()])

    // Same (identityId, requestId, responderDeviceId) key, but a different
    // manifestRoot -- must be rejected, never silently overwrite the original.
    await expect(store.offer(offer({ manifestRoot: 'root-b' }), now)).rejects.toThrow('conflicts with existing responder offer')
    expect(await store.pullOffers(pull('device-c', 'offers'), now)).toEqual([offer()])
  })

  test('expires requests and rejects an offer after its request has disappeared', async () => {
    const store = new MemoryRestoreControlStore(authorizer)
    await store.request(request({ expiresAt: '2026-08-21T00:01:00.000Z' }), new Date('2026-08-21T00:00:00.000Z'))
    await store.expire(new Date('2026-08-21T00:01:00.000Z'))
    expect(await store.pullRequests(pull('device-a', 'requests'))).toEqual([])
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
    expect(await store.pullRequests(pull('device-a', 'requests'), now)).toEqual([])
  })
})
