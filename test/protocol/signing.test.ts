import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/shared/protocol/canonical.ts'
import {
  ingressAckSigningBytes,
  vaultDeliveryAppendSigningBytes,
  vaultDeliveryPullSigningBytes,
  vaultDeliveryAckSigningBytes,
} from '../../src/shared/protocol/signing.ts'

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

  test('binds delivery append authorization to the payload hash, sender, and idempotency key', () => {
    const append = {
      version: 1 as const, identityId: 'did:web:alice.example', appendId: 'event-1', payload: new Uint8Array([1]),
      payloadHash: new Uint8Array([2]), senderDeviceId: 'device-a', sentAt: '2026-08-21T00:00:00.000Z',
    }
    expect(equalBytes(vaultDeliveryAppendSigningBytes(append), vaultDeliveryAppendSigningBytes({ ...append, payload: new Uint8Array([9]) }))).toBe(true)
    expect(equalBytes(vaultDeliveryAppendSigningBytes(append), vaultDeliveryAppendSigningBytes({ ...append, appendId: 'event-2' }))).toBe(false)
    expect(equalBytes(vaultDeliveryAppendSigningBytes(append), vaultDeliveryAppendSigningBytes({ ...append, senderDeviceId: 'device-b' }))).toBe(false)
  })

  test('binds delivery pulls to the recipient device and cursor', () => {
    const pull = { version: 1 as const, identityId: 'did:web:alice.example', recipientDeviceId: 'device-a', after: '7', requestedAt: '2026-08-21T00:00:00.000Z' }
    expect(equalBytes(vaultDeliveryPullSigningBytes(pull), vaultDeliveryPullSigningBytes({ ...pull, after: '8' }))).toBe(false)
    expect(equalBytes(vaultDeliveryPullSigningBytes(pull), vaultDeliveryPullSigningBytes({ ...pull, recipientDeviceId: 'device-b' }))).toBe(false)
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
