import { describe, expect, test } from 'bun:test'
import { equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { MailIngressProjector } from '../../src/mail/ingress-projector.ts'
import { decodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { ingestIngress } from '../../src/vault/ingress-ingest.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('mail ingress projector', () => {
  test('turns one opaque core ingress into raw-mail vault records and a sibling delivery outbox in the same ingress commit', async () => {
    const raw = new TextEncoder().encode('From: sender@example.test\r\nSubject: opaque to core\r\n\r\nhello')
    const envelope: IngressEnvelopeV1 = {
      version: 1, ingressId: 'ingress-1', protocol: 'mail', recipientIdentityId: identityId, recipientDeviceSnapshot: ['device-a'],
      createdAt: '2026-08-22T00:00:00.000Z', expiresAt: '2026-08-23T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([1]),
      protectedPayload: raw, protectedPayloadHash: sha256Bytes(raw),
    }
    const segmentKey = createSegmentKey()
    const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(9), segmentKey, {
      identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: envelope.createdAt,
    }, signer)
    const projector = new MailIngressProjector({
      identityId, actorDeviceId: 'device-a', async nextActorSeq() { return 1 }, async initialParents() { return [] },
      async activeSegment() { return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] } },
      async currentSnapshot() { return { state: 'state-0', mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 0, unreadEmails: 0 }], emails: [] } },
      signer, now: () => new Date('2026-08-22T00:01:00.000Z'),
    })
    let committed = false
    const result = await ingestIngress(envelope, signer, projector, {
      async commitIngress(input) {
        committed = true
        expect(input.objects).toHaveLength(2)
        expect(input.events).toHaveLength(1)
        expect(input.deliveryOutbox?.entryId).toBe(input.events[0].id)
        const pack = decodeVaultDeliveryPack(input.deliveryOutbox!.payload)
        expect(pack.objects.map(object => object.objectId)).toEqual(input.events[0].objectRefs)
        expect(input.projection).toMatchObject({ emails: [{ blobId: input.events[0].objectRefs[1] }] })
        return 'committed'
      },
    }, () => new Date('2026-08-22T00:01:01.000Z'))
    expect(committed).toBe(true)
    expect(result.ack.vaultEventId).toBeTruthy()
  })
})
