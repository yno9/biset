import { describe, expect, test } from 'bun:test'
import { sha256Bytes } from '../src/shared/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../src/shared/protocol/ingress.ts'
import type { IngressVaultCommit, VaultEventRecord } from '../src/client/store/vault/store.ts'
import { ingestTransportIngress } from '../src/client/store/vault/ingress-ingest.ts'

const identityId = 'did:webvh:test:alice.example'
const payload = new TextEncoder().encode('{"ciphertext":"opaque"}')
const envelope: IngressEnvelopeV1 = {
  version: 1,
  ingressId: 'sha256:mediator-queue-item',
  protocol: 'didcomm',
  recipientIdentityId: identityId,
  recipientDeviceSnapshot: [`${identityId}#device-1`],
  createdAt: '2026-08-27T00:00:00.000Z',
  expiresAt: '2026-08-28T00:00:00.000Z',
  transportMetadata: {},
  sourceEvidence: new Uint8Array(),
  protectedPayload: payload,
  protectedPayloadHash: sha256Bytes(payload),
}
const event: VaultEventRecord = {
  version: 1,
  id: 'sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  identityId,
  actorDeviceId: `${identityId}#device-1`,
  actorSeq: 1,
  kind: 'didcomm.control',
  targetIds: ['message-1'],
  objectRefs: [],
  parents: [],
  createdAt: envelope.createdAt,
  signature: new Uint8Array([1]),
}

describe('transport-owned ingress acknowledgement boundary', () => {
  test('atomically commits a mediator delivery without creating a core ACK outbox', async () => {
    let committed: IngressVaultCommit | undefined
    const result = await ingestTransportIngress(envelope, {
      async verifyAndProject() {
        return { objects: [], events: [event], projection: {}, jmapState: {}, checkpointId: 'checkpoint-1' }
      },
    }, {
      async readIngressReceipt() { return undefined },
      async commitIngress(input) { committed = input; return 'committed' },
    }, () => new Date('2026-08-27T00:00:01.000Z'))

    expect(result.result).toBe('committed')
    expect(committed?.receipt.ingressId).toBe(envelope.ingressId)
    expect(committed?.ackOutbox).toBeUndefined()
  })

  test('does not project a mediator redelivery whose durable receipt already exists', async () => {
    let projected = false
    let committed = false
    const result = await ingestTransportIngress(envelope, {
      async verifyAndProject() {
        projected = true
        return { objects: [], events: [event], projection: {}, jmapState: {}, checkpointId: 'checkpoint-1' }
      },
    }, {
      async readIngressReceipt() {
        return { identityId, ingressId: envelope.ingressId, protectedPayloadHash: envelope.protectedPayloadHash, vaultEventId: event.id, checkpointId: 'checkpoint-1', committedAt: envelope.createdAt }
      },
      async commitIngress() { committed = true; return 'committed' },
    })

    expect(result.result).toBe('already-committed')
    expect(projected).toBe(false)
    expect(committed).toBe(false)
  })

  test('rejects a mediator queue ID reused for different ciphertext', async () => {
    await expect(ingestTransportIngress(envelope, {
      async verifyAndProject() {
        throw new Error('must not project')
      },
    }, {
      async readIngressReceipt() {
        return { identityId, ingressId: envelope.ingressId, protectedPayloadHash: new Uint8Array(32), vaultEventId: event.id, checkpointId: 'checkpoint-1', committedAt: envelope.createdAt }
      },
      async commitIngress() { throw new Error('must not commit') },
    })).rejects.toThrow('reused with a different payload')
  })
})
