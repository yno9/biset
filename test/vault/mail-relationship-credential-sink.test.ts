import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import { decodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { MailRelationshipCredentialVaultSink } from '../../src/vault/mail-relationship-credential-sink.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('mail relationship credential vault sink', () => {
  test('atomically queues an encrypted credential for shared vault delivery without changing JMAP state', async () => {
    const segmentKey = createSegmentKey()
    const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(7), segmentKey, { identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z' }, signer)
    let committed: any
    const sink = new MailRelationshipCredentialVaultSink({
      identityId, actorDeviceId: 'device-a', async nextActorSeq() { return 3 }, async initialParents() { return ['event-2'] },
      async activeSegment() { return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] } },
      async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } }, signer,
      committer: { async commitLocalMutation(input) { committed = input; return 'committed' } },
    })
    const result = await sink.store({
      version: 1, kind: 'credential.mail-relationship', identityId, mediatorUrl: 'https://mail-mediator.example',
      address: 'y@biset.md', relationshipDid: 'did:peer:2.abc', privateKey: new Uint8Array(32).fill(1),
      edPrivateKey: new Uint8Array(32).fill(2), routeGeneration: 'gen-1', createdAt: '2026-08-21T00:00:00.000Z',
    })
    expect(result.event.kind).toBe('credential.mail-relationship.set')
    expect(committed.projection).toMatchObject({ state: 'state-1', emails: [] })
    const pack = decodeVaultDeliveryPack(committed.deliveryOutbox.payload)
    expect(pack.events).toMatchObject([{ kind: 'credential.mail-relationship.set' }])
    expect(pack.objects[0]?.ciphertext).not.toEqual(new Uint8Array(32).fill(1))
  })
})
