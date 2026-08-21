import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { LocalJmapGateway, LocalJmapTransport, MemoryLocalJmapReadModel } from '../../src/local-jmap/gateway.ts'
import { VaultBackedLocalJmapMutationSink } from '../../src/local-jmap/vault-mutation-sink.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import { decodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'

const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('VaultBackedLocalJmapMutationSink', () => {
  test('makes Email/set atomically describe encrypted events and a new local projection', async () => {
    let sequence = 0
    let committed: Record<string, unknown> | undefined
    const sink = new VaultBackedLocalJmapMutationSink({
      accountId: 'biset:did:web:alice.example',
      identityId: 'did:web:alice.example',
      actorDeviceId: 'device-a',
      async nextActorSeq() { sequence += 1; return sequence },
      async initialParents() { return ['event-base'] },
      async activeSegment() {
        const segmentKey = createSegmentKey()
        return {
          segmentId: 'segment-1',
          segmentKey,
          keyWraps: [await createSegmentKeyWrap(new Uint8Array(32).fill(7), segmentKey, {
            identityId: 'did:web:alice.example', selfGroupId: 'self-group-1', segmentId: 'segment-1',
            sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z',
          }, signer)],
        }
      },
      signer,
      committer: { async commitLocalMutation(input) { committed = input as unknown as Record<string, unknown>; return 'committed' } },
      now: () => new Date('2026-08-21T00:00:00.000Z'),
    })
    const model = new MemoryLocalJmapReadModel({
      state: 'state-1',
      mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 1, unreadEmails: 1 }],
      emails: [{ id: 'email-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' }],
    })
    const transport = new LocalJmapTransport(new LocalJmapGateway({
      accountId: 'biset:did:web:alice.example', identityId: 'did:web:alice.example', readModel: model, mutationSink: sink,
    }))
    const response = await transport.call<{ methodResponses: Array<[string, Record<string, unknown>, string]> }>([
      { name: 'Email/set', arguments: { accountId: 'biset:did:web:alice.example', update: { 'email-1': { keywords: { '$seen': true } } } }, callId: 'set-1' },
    ])
    expect(response.methodResponses[0][0]).toBe('Email/set')
    expect(response.methodResponses[0][1]).toMatchObject({ oldState: 'state-1', updated: { 'email-1': null } })
    expect((committed?.events as unknown[])).toHaveLength(1)
    expect((committed?.objects as unknown[])).toHaveLength(1)
    const deliveryOutbox = committed?.deliveryOutbox as { payload: Uint8Array; attempts: number }
    expect(deliveryOutbox.attempts).toBe(0)
    expect(decodeVaultDeliveryPack(deliveryOutbox.payload)).toMatchObject({
      identityId: 'did:web:alice.example', objects: [{ segmentId: 'segment-1' }], events: [{ kind: 'keyword.set' }], keyWraps: [{ recipientEpoch: '1' }],
    })
    expect((committed?.projection as { emails: Array<{ keywords: unknown }> }).emails[0].keywords).toEqual({ '$seen': true })
  })
})
