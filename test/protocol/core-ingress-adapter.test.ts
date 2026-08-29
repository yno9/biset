import { describe, expect, test } from 'bun:test'
import { CoreIngressAdapter } from '../../src/core/adapters/ingress.ts'
import { MemoryTrustedDeviceRoster } from '../../src/core/identity/device-roster.ts'
import type { IngressStore } from '../../src/core/mediation/ingress-store.ts'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import type { AdapterIngressOfferV1, IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'

const identityId = 'did:web:alice.example'
const body = new Uint8Array([1, 2, 3])

function offer(overrides: Partial<AdapterIngressOfferV1> = {}): AdapterIngressOfferV1 {
  return {
    version: 1,
    ingressId: 'ingress-1',
    protocol: 'mail',
    recipientIdentityId: identityId,
    createdAt: '2026-08-21T00:00:00.000Z',
    expiresAt: '2026-08-22T00:00:00.000Z',
    transportMetadata: { envelope: 'opaque' },
    sourceEvidence: new Uint8Array([9]),
    protectedPayload: body,
    protectedPayloadHash: sha256Bytes(body),
    ...overrides,
  }
}

function captureStore(target: IngressEnvelopeV1[]): IngressStore {
  return {
    async offer(envelope) { target.push(envelope) },
    async pull() { return [] },
    async acknowledge() { throw new Error('not used') },
    async expire() { return [] },
    async status() { return undefined },
  }
}

describe('core ingress adapter', () => {
  test('freezes recipients from the accepted self-group roster, not adapter input', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    await roster.installAcceptedProjection({
      version: 1,
      identityId,
      selfGroupId: 'self-group-1',
      epoch: '1',
      acceptedAt: '2026-08-21T00:00:00.000Z',
      devices: [
        { deviceId: 'device-a', deliveryFloor: '1', signingPublicKey: new Uint8Array(32).fill(1), deviceCredential: new Uint8Array([1]) },
        { deviceId: 'device-b', deliveryFloor: '1', signingPublicKey: new Uint8Array(32).fill(2), deviceCredential: new Uint8Array([2]) },
      ],
    })
    const captured: IngressEnvelopeV1[] = []
    const adapter = new CoreIngressAdapter(roster, captureStore(captured))

    await adapter.offer(offer())

    expect(captured).toHaveLength(1)
    expect(captured[0]?.recipientDeviceSnapshot).toEqual(['device-a', 'device-b'])
    await expect(adapter.offer({ ...offer({ ingressId: 'ingress-2' }), recipientDeviceSnapshot: ['attacker-device'] } as never)).rejects.toThrow('unknown field')
    expect(captured).toHaveLength(1)
  })

  test('rejects ingress for an identity without an accepted device roster', async () => {
    const adapter = new CoreIngressAdapter(new MemoryTrustedDeviceRoster(), captureStore([]))
    await expect(adapter.offer(offer())).rejects.toThrow('no trusted devices')
  })
})
