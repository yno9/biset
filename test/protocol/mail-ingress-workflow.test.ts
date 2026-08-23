import { describe, expect, test } from 'bun:test'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { synchronizeMailIngress } from '../../src/mail/ingress-workflow.ts'
import type { IngressAckOutboxRecord, VaultDeliveryOutboxRecord } from '../../src/vault/store.ts'

const identityId = 'did:web:alice.example'
const deviceId = 'device-a'
const envelope: IngressEnvelopeV1 = {
  version: 1, ingressId: 'ingress-1', protocol: 'mail', recipientIdentityId: identityId, recipientDeviceSnapshot: [deviceId],
  createdAt: '2026-08-22T00:00:00.000Z', expiresAt: '2026-08-23T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([1]),
  protectedPayload: new Uint8Array([2]), protectedPayloadHash: sha256Bytes(new Uint8Array([2])),
}

describe('mail ingress workflow', () => {
  test('commits and ACKs claimed mail before appending the resulting vault pack for sibling devices', async () => {
    const events: string[] = []
    const ingressAcks: IngressAckOutboxRecord[] = []
    const deliveries: VaultDeliveryOutboxRecord[] = []
    const signer = {
      deviceId,
      async sign() { return new Uint8Array([9]) },
    }
    const output = await synchronizeMailIngress({
      identityId, deviceId, signer,
      store: {
        async readIngressAckOutbox() { return ingressAcks.map(value => ({ ...value, ack: { ...value.ack } })) },
        async removeIngressAckOutbox(_identityId, ingressId) { ingressAcks.splice(ingressAcks.findIndex(value => value.ingressId === ingressId), 1) },
        async noteIngressAckOutboxAttempt() { throw new Error('must not retry') },
        async readDeliveryOutbox() { return deliveries.map(value => ({ ...value, payload: value.payload.slice(), payloadHash: value.payloadHash.slice() })) },
        async removeDeliveryOutbox(_identityId, entryId) { deliveries.splice(deliveries.findIndex(value => value.entryId === entryId), 1) },
        async noteDeliveryOutboxAttempt() { throw new Error('must not retry') },
      },
      ingressTransport: {
        async pull() { events.push('pull'); return [envelope] },
        async acknowledge() { events.push('ack') },
      },
      deliveryTransport: {
        async append() { events.push('append') },
      },
      projector: {
        async verifyAndProject() {
          events.push('project')
          return {
            objects: [],
            events: [{ version: 1, id: 'event-1', identityId, actorDeviceId: deviceId, actorSeq: 1, kind: 'message.add', targetIds: ['mail-1'], objectRefs: [], parents: [], createdAt: envelope.createdAt, signature: new Uint8Array([1]) }],
            projection: {}, jmapState: {}, checkpointId: 'checkpoint-1',
            deliveryOutbox: { identityId, entryId: 'event-1', payload: new Uint8Array([7]), payloadHash: sha256Bytes(new Uint8Array([7])), createdAt: envelope.createdAt, attempts: 0 },
          }
        },
      },
      committer: {
        async commitIngress(input) {
          events.push('commit')
          ingressAcks.push(input.ackOutbox)
          deliveries.push(input.deliveryOutbox!)
          return 'committed'
        },
      },
      now: () => new Date('2026-08-22T00:01:00.000Z'),
    })
    expect(events).toEqual(['pull', 'project', 'commit', 'ack', 'append'])
    expect(output.ingress.ingestedIngressIds).toEqual(['ingress-1'])
    expect(output.deliveryAfter.appendedEntryIds).toEqual(['event-1'])
    expect(ingressAcks).toEqual([])
    expect(deliveries).toEqual([])
  })
})
