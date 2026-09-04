import { describe, expect, test } from 'bun:test'
import { CoreIngressTransport } from '../src/vault/core-ingress-transport.ts'
import type { IngressAckV1 } from '../src/protocol/ingress.ts'

const ack: IngressAckV1 = {
  version: 1,
  ingressId: 'ingress-1',
  recipientDeviceId: 'did:webvh:scid:alice.example#device-1',
  protectedPayloadHash: new Uint8Array(32),
  vaultEventId: 'event-1',
  checkpointId: 'checkpoint-1',
  ackedAt: '2026-08-27T00:00:00.000Z',
  signature: new Uint8Array(64),
}

describe('CoreIngressTransport ACK tombstones', () => {
  for (const body of [
    'unknown ingressId',
    'ingress is already vault-ingested',
    'ingress is already expired',
    'ingress is already rejected',
  ]) {
    test(`treats ${body} as terminal success`, async () => {
      const transport = new CoreIngressTransport({
        baseUrl: 'https://core.example',
        fetch: async () => new Response(body, { status: 400 }),
      })
      await expect(transport.acknowledge(ack)).resolves.toBeUndefined()
    })
  }

  test('keeps a non-terminal validation failure retryable', async () => {
    const transport = new CoreIngressTransport({
      baseUrl: 'https://core.example',
      fetch: async () => new Response('ACK is not authorised', { status: 400 }),
    })
    await expect(transport.acknowledge(ack)).rejects.toThrow('ACK is not authorised')
  })
})
