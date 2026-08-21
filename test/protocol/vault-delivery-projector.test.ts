import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { VaultDeliveryProjector } from '../../src/vault/delivery-projector.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { buildVaultMutation } from '../../src/vault/mutations.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'

const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

const identityId = 'did:web:alice.example'
const segmentKey = createSegmentKey()

describe('vault delivery projector', () => {
  test('verifies a current MLS wrap and signed event before decrypting the mutation into the local projection', async () => {
    const event = await buildVaultMutation({ kind: 'keyword.set', targetIds: ['email-1'], payload: { emailId: 'email-1', keywords: { '$seen': true } } }, {
      identityId, actorDeviceId: 'device-a', actorSeq: 1, parents: ['event-base'], segmentId: 'segment-1', segmentKey, createdAt: '2026-08-21T00:00:00.000Z',
    }, signer)
    const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(7), segmentKey, {
      identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z',
    }, signer)
    const projector = new VaultDeliveryProjector({
      identityId,
      async currentSnapshot() {
        return { state: 'state-0', mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 1, unreadEmails: 1 }], emails: [{ id: 'email-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' }] }
      },
      epochs: {
        async currentVaultEpoch() { return { selfGroupId: 'self-group-1', epoch: '1' } },
        async deriveVaultEpochKey() { return new Uint8Array(32).fill(7) },
      },
      verifier: signer,
    })
    const output = await projector.verifyAndProject({ version: 1, identityId, objects: [{ ...event.object, identityId }], events: [event.event], keyWraps: [wrap] })
    expect(output.projection.emails[0].keywords).toEqual({ '$seen': true })
    expect(output.checkpointId).toBe(output.projection.state)
  })

  test('does not accept a current-epoch mismatch before attempting an object decrypt', async () => {
    const projector = new VaultDeliveryProjector({
      identityId,
      async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [] } },
      epochs: {
        async currentVaultEpoch() { return { selfGroupId: 'self-group-1', epoch: '2' } },
        async deriveVaultEpochKey() { throw new Error('must not derive') },
      },
      verifier: signer,
    })
    await expect(projector.verifyAndProject({ version: 1, identityId, objects: [], events: [], keyWraps: [{
      version: 1, identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', nonce: new Uint8Array([1]), aad: new Uint8Array([1]), wrappedSegmentKey: new Uint8Array([1]), grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([1]),
    }] })).rejects.toThrow('not for the current MLS epoch')
  })
})
