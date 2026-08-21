import { describe, expect, test } from 'bun:test'
import { createVaultDeliveryHttpHandler } from '../../src/core/mediation/vault-delivery-http.ts'
import { CoreVaultDeliveryTransport } from '../../src/vault/core-delivery-transport.ts'
import type { VaultDeliveryStore } from '../../src/core/mediation/vault-delivery-store.ts'
import type { DeliveryPullResult, VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryPullV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const append: VaultDeliveryAppendV1 = { version: 1, identityId, appendId: 'event-1', payload: new Uint8Array([1]), payloadHash: new Uint8Array([2]), senderDeviceId: 'device-a', sentAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([3]) }
const pull: VaultDeliveryPullV1 = { version: 1, identityId, recipientDeviceId: 'device-b', after: '0', requestedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([4]) }
const ack: VaultDeliveryAckV1 = { version: 1, identityId, seq: '1', payloadHash: new Uint8Array([2]), recipientDeviceId: 'device-b', checkpointId: 'checkpoint-1', ackedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([5]) }

describe('bounded vault delivery HTTP adapter', () => {
  test('connects the client transport only to append, pull, and ACK operations', async () => {
    const calls: string[] = []
    const store: VaultDeliveryStore = {
      async append(input) { calls.push(`append:${input.appendId}`); return { version: 1, identityId, seq: '1', payload: input.payload, payloadHash: input.payloadHash, createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z' } },
      async pull(input): Promise<DeliveryPullResult> { calls.push(`pull:${input.after}`); return { kind: 'items', items: [], nextCursor: input.after, retainedFrom: '1', latestSeq: '0' } },
      async acknowledge(input) { calls.push(`ack:${input.seq}`) },
      async expire() {},
      async status() { return { identityId, latestSeq: '0', retainedFrom: '1', payloadBytes: 0, pendingItems: 0 } },
    }
    const handler = createVaultDeliveryHttpHandler(store)
    const transport = new CoreVaultDeliveryTransport({
      baseUrl: 'https://core.example',
      fetch: (input, init) => handler(new Request(input, init)),
    })
    await transport.append(append)
    expect(await transport.pull(pull)).toEqual({ kind: 'items', items: [], nextCursor: '0', retainedFrom: '1', latestSeq: '0' })
    await transport.acknowledge(ack)
    expect(calls).toEqual(['append:event-1', 'pull:0', 'ack:1'])
  })

  test('rejects unknown HTTP paths without turning the core into a history API', async () => {
    const handler = createVaultDeliveryHttpHandler({} as VaultDeliveryStore)
    expect((await handler(new Request('https://core.example/v1/Email/query', { method: 'POST', body: '{}' }))).status).toBe(404)
  })
})
