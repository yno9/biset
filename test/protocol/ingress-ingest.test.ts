import { describe, expect, test } from 'bun:test'
import { equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import { ingressAckSigningBytes } from '../../src/protocol/signing.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { ingestIngress } from '../../src/vault/ingress-ingest.ts'

const body = new Uint8Array([1, 2])
const envelope: IngressEnvelopeV1 = { version: 1, ingressId: 'ingress-1', protocol: 'mail', recipientIdentityId: 'did:web:alice.example', recipientDeviceSnapshot: ['device-a'], createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([3]), protectedPayload: body, protectedPayloadHash: sha256Bytes(body) }

describe('external ingress ingest', () => {
  test('makes the signed ACK durable only with the verified vault transaction', async () => {
    let committed = false
    const output = await ingestIngress(envelope, {
      deviceId: 'device-a', async sign(bytes) { return sha256Bytes(bytes) },
    }, {
      async verifyAndProject() {
        expect(committed).toBe(false)
        return {
          objects: [],
          events: [{ version: 1, id: 'event-1', identityId: envelope.recipientIdentityId, actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add', targetIds: ['message-1'], objectRefs: [], parents: [], createdAt: envelope.createdAt, signature: new Uint8Array([4]) }],
          projection: { messages: ['message-1'] }, jmapState: { state: 'state-1' }, checkpointId: 'checkpoint-1',
        }
      },
    }, {
      async commitIngress(input) {
        expect(input.ackOutbox.ack.vaultEventId).toBe('event-1')
        const { signature, ...unsigned } = input.ackOutbox.ack
        expect(equalBytes(signature, sha256Bytes(ingressAckSigningBytes(unsigned)))).toBe(true)
        committed = true
        return 'committed'
      },
    }, () => new Date('2026-08-21T01:00:00.000Z'))
    expect(committed).toBe(true)
    expect(output.ack.checkpointId).toBe('checkpoint-1')
  })

  test('rejects a tampered protected body before protocol decoding or ACK creation', async () => {
    await expect(ingestIngress({ ...envelope, protectedPayloadHash: new Uint8Array([9]) }, { deviceId: 'device-a', async sign() { return new Uint8Array([1]) } }, {
      async verifyAndProject() { throw new Error('must not decode') },
    }, {
      async commitIngress() { throw new Error('must not commit') },
    })).rejects.toThrow('ingress envelope is invalid')
  })
})
