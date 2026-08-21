import { describe, expect, test } from 'bun:test'
import { createRestoreControlHttpHandler } from '../../src/core/mediation/restore-control-http.ts'
import { MemoryRestoreControlStore, type RestoreControlAuthorizer } from '../../src/core/mediation/restore-control-store.ts'
import { CoreRestoreControlTransport } from '../../src/vault/core-restore-control-transport.ts'
import type { RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const authorizer: RestoreControlAuthorizer = {
  async isTrustedDevice(_identityId, deviceId) { return ['device-a', 'device-c'].includes(deviceId) },
  async verifyRequest(value) { return value.signature[0] === 1 },
  async verifyOffer(value) { return value.signature[0] === 2 },
  async verifyCancel(value) { return value.signature[0] === 3 },
  async verifyPull(value) { return value.signature[0] === 4 },
}
const request: RestoreRequestV1 = { version: 1, requestId: 'restore-1', identityId, requesterDeviceId: 'device-c', reason: 'ttl-expired', requestedAt: '2099-08-21T00:00:00.000Z', expiresAt: '2099-08-21T00:15:00.000Z', signature: new Uint8Array([1]) }
const offer: RestoreOfferV1 = { version: 1, requestId: 'restore-1', identityId, requesterDeviceId: 'device-c', responderDeviceId: 'device-a', manifestRoot: 'root-a', offeredAt: '2099-08-21T00:01:00.000Z', expiresAt: '2099-08-21T00:10:00.000Z', signature: new Uint8Array([2]) }
const pull: RestoreControlPullV1 = { version: 1, identityId, deviceId: 'device-a', kind: 'requests', requestedAt: '2099-08-21T00:02:00.000Z', signature: new Uint8Array([4]) }

describe('restore control HTTP adapter', () => {
  test('relays signed small controls but exposes no vault transfer endpoint', async () => {
    const handler = createRestoreControlHttpHandler(new MemoryRestoreControlStore(authorizer))
    const transport = new CoreRestoreControlTransport({ baseUrl: 'https://core.example', fetch: (input, init) => handler(new Request(input, init)) })
    await transport.request(request)
    expect(await transport.pullRequests(pull)).toEqual([request])
    await transport.offer(offer)
    expect(await transport.pullOffers({ ...pull, deviceId: 'device-c', kind: 'offers' })).toEqual([offer])
    expect((await handler(new Request('https://core.example/v1/restore/chunks', { method: 'POST', body: '{}' }))).status).toBe(404)
  })
})
