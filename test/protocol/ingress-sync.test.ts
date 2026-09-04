import { describe, expect, test } from 'bun:test'
import type { IngressAckV1, IngressEnvelopeV1 } from '../../src/shared/protocol/ingress.ts'
import { synchronizeIngress } from '../../src/vault/ingress-sync.ts'
import type { IngressAckOutboxReader, IngressAckOutboxRecord } from '../../src/vault/store.ts'

const identityId = 'did:web:alice.example'
const deviceId = 'device-a'
const signer = { deviceId, async sign() { return new Uint8Array([7]) } }

function envelope(ingressId: string): IngressEnvelopeV1 {
  return {
    version: 1, ingressId, protocol: 'mail', recipientIdentityId: identityId, recipientDeviceSnapshot: [deviceId],
    createdAt: '2026-08-22T00:00:00.000Z', expiresAt: '2026-08-23T00:00:00.000Z', transportMetadata: {},
    sourceEvidence: new Uint8Array([1]), protectedPayload: new Uint8Array([2]), protectedPayloadHash: new Uint8Array([3]),
  }
}

function record(ingressId: string): IngressAckOutboxRecord {
  const ack: IngressAckV1 = { version: 1, ingressId, protectedPayloadHash: new Uint8Array([3]), recipientDeviceId: deviceId, vaultEventId: `event-${ingressId}`, checkpointId: `state-${ingressId}`, ackedAt: '2026-08-22T00:01:00.000Z', signature: new Uint8Array([4]) }
  return { identityId, ingressId, ack, attempts: 0, createdAt: ack.ackedAt }
}

class MemoryIngressAcks implements IngressAckOutboxReader {
  constructor(readonly records: IngressAckOutboxRecord[]) {}
  async readIngressAckOutbox() { return this.records.map(record => ({ ...record, ack: { ...record.ack } })) }
  async removeIngressAckOutbox(_identityId: string, ingressId: string) { this.records.splice(this.records.findIndex(record => record.ingressId === ingressId), 1) }
  async noteIngressAckOutboxAttempt(_identityId: string, ingressId: string) { this.records.find(record => record.ingressId === ingressId)!.attempts += 1 }
}

describe('external ingress synchronisation', () => {
  test('flushes durable ACKs around a claimed pull and never ACKs before its ingestor completes', async () => {
    const outbox = new MemoryIngressAcks([record('old')])
    const acknowledged: string[] = []
    let committed = false
    const output = await synchronizeIngress(outbox, {
      async pull() { return [envelope('new')] },
      async acknowledge(ack) { acknowledged.push(ack.ingressId); if (ack.ingressId === 'new') expect(committed).toBe(true) },
    }, {
      async ingest(value) { expect(value.ingressId).toBe('new'); committed = true; outbox.records.push(record('new')) },
    }, signer, identityId, deviceId)
    expect(output).toEqual({ ingestedIngressIds: ['new'] })
    expect(acknowledged).toEqual(['old', 'new'])
    expect(outbox.records).toEqual([])
  })

  test('retains a failed ACK for a later wake without pretending the durable ingress did not happen', async () => {
    const outbox = new MemoryIngressAcks([])
    const output = await synchronizeIngress(outbox, {
      async pull() { return [envelope('new')] },
      async acknowledge() { throw new Error('offline') },
    }, {
      async ingest() { outbox.records.push(record('new')) },
    }, signer, identityId, deviceId)
    expect(output).toEqual({ ingestedIngressIds: ['new'], pendingAckIngressId: 'new' })
    expect(outbox.records[0].attempts).toBe(1)
  })
})
