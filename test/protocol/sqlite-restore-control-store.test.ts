import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { SqliteRestoreControlStore } from '../../src/core/mediation/sqlite-restore-control-store.ts'
import type { RestoreControlAuthorizer } from '../../src/core/mediation/restore-control-store.ts'
import type { RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1 } from '../../src/protocol/vault.ts'

const path = `/tmp/biset-restore-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const authorizer: RestoreControlAuthorizer = {
  async isTrustedDevice(_identityId, deviceId) { return ['device-a', 'device-b', 'device-c'].includes(deviceId) },
  async verifyRequest(value) { return value.signature[0] === 1 },
  async verifyOffer(value) { return value.signature[0] === 2 },
  async verifyCancel(value) { return value.signature[0] === 3 },
  async verifyPull(value) { return value.signature[0] === 4 },
}

function request(overrides: Partial<RestoreRequestV1> = {}): RestoreRequestV1 {
  return { version: 1, requestId: 'restore-1', identityId, requesterDeviceId: 'device-c', reason: 'ttl-expired', knownManifestRoot: 'root-c', requestedAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-21T00:15:00.000Z', signature: new Uint8Array([1]), ...overrides }
}

function offer(overrides: Partial<RestoreOfferV1> = {}): RestoreOfferV1 {
  return { version: 1, requestId: 'restore-1', identityId, requesterDeviceId: 'device-c', responderDeviceId: 'device-a', manifestRoot: 'root-a', offeredAt: '2026-08-21T00:01:00.000Z', expiresAt: '2026-08-21T00:10:00.000Z', signature: new Uint8Array([2]), ...overrides }
}

function pull(deviceId: string, kind: RestoreControlPullV1['kind']): RestoreControlPullV1 {
  return { version: 1, identityId, deviceId, kind, requestedAt: '2026-08-21T00:02:00.000Z', signature: new Uint8Array([4]) }
}

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

describe('SQLite restore control store push notifier', () => {
  test('notifies on a genuinely new request, not on a resubmit, and swallows notifier failures', async () => {
    let calls = 0
    const notifier = {
      async notifyPendingRestore() {
        calls += 1
        throw new Error('push transport unavailable')
      },
    }
    const store = SqliteRestoreControlStore.open(path, authorizer, undefined, notifier)
    const now = new Date('2026-08-21T00:00:00.000Z')
    await expect(store.request(request(), now)).resolves.toBeUndefined()
    expect(calls).toBe(1)
    await store.request(request(), now)
    expect(calls).toBe(1)
    store.close()
  })
})

describe('SQLite restore control store', () => {
  test('survives restart while retaining only small signed controls', async () => {
    const first = SqliteRestoreControlStore.open(path, authorizer)
    const now = new Date('2026-08-21T00:00:00.000Z')
    await first.request(request(), now)
    await first.offer(offer(), now)
    await expect(first.offer(offer({ responderDeviceId: 'device-b', expiresAt: '2026-08-21T00:16:00.000Z' }), now)).rejects.toThrow('cannot outlive')
    first.close()

    const restarted = SqliteRestoreControlStore.open(path, authorizer)
    expect(await restarted.pullRequests(pull('device-a', 'requests'), now)).toEqual([request()])
    expect(await restarted.pullOffers(pull('device-c', 'offers'), now)).toEqual([offer()])
    restarted.close()
  })

  test('resubmitting an identical offer is a silent no-op; resubmitting a conflicting one is rejected', async () => {
    const store = SqliteRestoreControlStore.open(path, authorizer)
    const now = new Date('2026-08-21T00:00:00.000Z')
    await store.request(request(), now)
    await store.offer(offer(), now)

    await expect(store.offer(offer(), now)).resolves.toBeUndefined()
    expect(await store.pullOffers(pull('device-c', 'offers'), now)).toEqual([offer()])

    await expect(store.offer(offer({ manifestRoot: 'root-b' }), now)).rejects.toThrow('conflicts with existing responder offer')
    expect(await store.pullOffers(pull('device-c', 'offers'), now)).toEqual([offer()])
    store.close()
  })

  test('requires a signed poll and removes expired controls after restart', async () => {
    const first = SqliteRestoreControlStore.open(path, authorizer)
    await first.request(request({ expiresAt: '2026-08-21T00:01:00.000Z' }), new Date('2026-08-21T00:00:00.000Z'))
    first.close()

    const restarted = SqliteRestoreControlStore.open(path, authorizer)
    await expect(restarted.pullRequests({ ...pull('device-a', 'requests'), signature: new Uint8Array([9]) })).rejects.toThrow('signature is invalid')
    expect(await restarted.pullRequests(pull('device-a', 'requests'), new Date('2026-08-21T00:01:00.000Z'))).toEqual([])
    restarted.close()
  })

  test('bounds active requests and cascades a requester cancellation to its offers', async () => {
    const store = SqliteRestoreControlStore.open(path, authorizer, { maxIdentityRequests: 1, maxOffersPerRequest: 1 })
    const now = new Date('2026-08-21T00:00:00.000Z')
    await store.request(request(), now)
    await store.offer(offer(), now)
    await expect(store.request(request({ requestId: 'restore-2' }), now)).rejects.toThrow('limit reached')
    const cancel: RestoreCancelV1 = { version: 1, requestId: 'restore-1', identityId, requesterDeviceId: 'device-c', cancelledAt: '2026-08-21T00:02:00.000Z', signature: new Uint8Array([3]) }
    await store.cancel(cancel, now)
    expect(await store.pullOffers(pull('device-c', 'offers'), now)).toEqual([])
    store.close()
  })
})
