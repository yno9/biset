import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import {
  ingressAckSigningBytes,
  restoreCancelSigningBytes,
  restoreOfferSigningBytes,
  restoreRequestSigningBytes,
  vaultDeliveryAckSigningBytes,
} from '../../src/protocol/signing.ts'

describe('device-control signing bytes', () => {
  test('binds delivery ACKs to their exact payload and device', () => {
    const ack = {
      version: 1 as const,
      identityId: 'did:web:alice.example',
      seq: '7',
      payloadHash: new Uint8Array([1, 2, 3]),
      recipientDeviceId: 'device-a',
      checkpointId: 'checkpoint-a',
      ackedAt: '2026-08-21T00:00:00.000Z',
    }
    expect(vaultDeliveryAckSigningBytes(ack)).toEqual(vaultDeliveryAckSigningBytes({ ...ack, payloadHash: ack.payloadHash.slice() }))
    expect(equalBytes(vaultDeliveryAckSigningBytes(ack), vaultDeliveryAckSigningBytes({ ...ack, seq: '8' }))).toBe(false)
    expect(equalBytes(vaultDeliveryAckSigningBytes(ack), vaultDeliveryAckSigningBytes({ ...ack, recipientDeviceId: 'device-b' }))).toBe(false)
  })

  test('separates restore request, offer, and cancel messages by type and all expiry fields', () => {
    const request = {
      version: 1 as const,
      requestId: 'restore-1',
      identityId: 'did:web:alice.example',
      requesterDeviceId: 'device-a',
      reason: 'ttl-expired' as const,
      requestedAt: '2026-08-21T00:00:00.000Z',
      expiresAt: '2026-08-21T00:15:00.000Z',
    }
    const offer = {
      version: 1 as const,
      requestId: 'restore-1',
      identityId: 'did:web:alice.example',
      requesterDeviceId: 'device-a',
      responderDeviceId: 'device-b',
      manifestRoot: 'root-b',
      offeredAt: '2026-08-21T00:01:00.000Z',
      expiresAt: '2026-08-21T00:10:00.000Z',
    }
    const cancel = {
      version: 1 as const,
      requestId: 'restore-1',
      identityId: 'did:web:alice.example',
      requesterDeviceId: 'device-a',
      cancelledAt: '2026-08-21T00:02:00.000Z',
    }
    expect(equalBytes(restoreRequestSigningBytes(request), restoreRequestSigningBytes({ ...request, expiresAt: '2026-08-21T00:16:00.000Z' }))).toBe(false)
    expect(equalBytes(restoreRequestSigningBytes(request), restoreOfferSigningBytes(offer))).toBe(false)
    expect(equalBytes(restoreOfferSigningBytes(offer), restoreCancelSigningBytes(cancel))).toBe(false)
  })

  test('does not let an ingress ACK signature be reused as a vault delivery ACK', () => {
    const ingress = ingressAckSigningBytes({
      version: 1,
      ingressId: 'ingress-1',
      protectedPayloadHash: new Uint8Array([1]),
      recipientDeviceId: 'device-a',
      vaultEventId: 'event-1',
      checkpointId: 'checkpoint-a',
      ackedAt: '2026-08-21T00:00:00.000Z',
    })
    const delivery = vaultDeliveryAckSigningBytes({
      version: 1,
      identityId: 'did:web:alice.example',
      seq: '1',
      payloadHash: new Uint8Array([1]),
      recipientDeviceId: 'device-a',
      checkpointId: 'checkpoint-a',
      ackedAt: '2026-08-21T00:00:00.000Z',
    })
    expect(equalBytes(ingress, delivery)).toBe(false)
  })
})
