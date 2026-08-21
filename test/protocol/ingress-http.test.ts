import { describe, expect, test } from 'bun:test'
import { createIngressHttpHandler } from '../../src/core/mediation/ingress-http.ts'
import type { IngressStore } from '../../src/core/mediation/ingress-store.ts'
import { CoreIngressTransport } from '../../src/vault/core-ingress-transport.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../../src/protocol/ingress.ts'

const identityId = 'did:web:alice.example'
const pull: IngressPullV1 = { version: 1, identityId, recipientDeviceId: 'device-a', requestedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([1]) }
const ack: IngressAckV1 = { version: 1, ingressId: 'ingress-1', protectedPayloadHash: new Uint8Array([2]), recipientDeviceId: 'device-a', vaultEventId: 'event-1', checkpointId: 'checkpoint-1', ackedAt: '2026-08-21T00:01:00.000Z', signature: new Uint8Array([3]) }
const envelope: IngressEnvelopeV1 = { version: 1, ingressId: 'ingress-1', protocol: 'mail', recipientIdentityId: identityId, recipientDeviceSnapshot: ['device-a'], createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([4]), protectedPayload: new Uint8Array([5]), protectedPayloadHash: new Uint8Array([2]) }

describe('bounded ingress HTTP adapter', () => {
  test('exposes only endpoint-signed pull and durable ACK, never an offer route', async () => {
    const calls: string[] = []
    const store: IngressStore = {
      async offer() { throw new Error('not reachable over HTTP') },
      async pull(value) { calls.push(`pull:${value.recipientDeviceId}`); return [envelope] },
      async acknowledge(value) { calls.push(`ack:${value.ingressId}`); return { ingressId: value.ingressId, identityId, status: 'vault-ingested', expiresAt: envelope.expiresAt, payloadRetained: false } },
      async expire() { return [] },
      async status() { return undefined },
    }
    const handler = createIngressHttpHandler(store)
    const transport = new CoreIngressTransport({ baseUrl: 'https://core.example', fetch: (input, init) => handler(new Request(input, init)) })

    expect(await transport.pull(pull)).toEqual([envelope])
    await transport.acknowledge(ack)
    expect(calls).toEqual(['pull:device-a', 'ack:ingress-1'])
    expect((await handler(new Request('https://core.example/v1/ingress/offer', { method: 'POST', body: '{}' }))).status).toBe(404)
  })
})
