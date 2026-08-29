// MailMediatorSubmissionTransport, driven against a real in-process Mail
// Mediator (submit-status-request polling included) with the same
// in-memory Vault reader/sink shape as test/identity/mail-relationship.test.ts.
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { createMailMediator } from '../../src/mail-mediator/server.ts'
import type { DidCommSender } from '../../src/didcomm/mediator-transport.ts'
import { MailRelationshipCredentialReader } from '../../src/vault/mail-relationship-credential-reader.ts'
import { MailRelationshipCredentialVaultSink } from '../../src/vault/mail-relationship-credential-sink.ts'
import { MailMediatorSubmissionTransport } from '../../src/vault/mail-mediator-submission-transport.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { equalBytes } from '../../src/protocol/canonical.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import type { RecipientResult } from '../../src/mail-mediator/submission-store.ts'

const segmentId = 'segment-1'
const segmentKey = createSegmentKey()
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}
const ADDRESS = 'y@biset.md'

function freshMailMediator(submitOutbound: (record: { rcptTo: string[] }) => Promise<RecipientResult[]>) {
  const url = `https://mail-mediator-${crypto.randomUUID()}.test.example`
  const mediatorIdentity = generatePeerIdentity({ uri: url, accept: ['didcomm/v2'] })
  const frontDoorPeer = generatePeerIdentity()
  const { handle } = createMailMediator({
    mediator: mediatorIdentity,
    resolveMailOperationalKid: async kid => (kid === frontDoorPeer.xKid ? { address: ADDRESS, publicKey: frontDoorPeer.xPub } : null),
    submitOutbound: record => submitOutbound(record),
  })
  const fetchImpl: typeof fetch = async (input, init) => {
    const reqUrl = new URL(String(input))
    const res = await handle(new Request(reqUrl, init), reqUrl)
    return res ?? new Response('not found', { status: 404 })
  }
  return { url, frontDoor: { did: frontDoorPeer.did, xKid: frontDoorPeer.xKid, xPriv: frontDoorPeer.xPriv } satisfies DidCommSender, fetchImpl }
}

function makeReaderSink(identityId: string): { reader: MailRelationshipCredentialReader; sink: MailRelationshipCredentialVaultSink } {
  const records: Array<{ event: any; object: any }> = []
  const objects = new Map<string, any>()

  const reader = new MailRelationshipCredentialReader({
    identityId,
    objects: { async readObject(_identityId, objectId) { return objects.get(objectId) } },
    events: { async readCredentialEvents() { return records.map(r => ({ ...r.event, identityId, targetIds: [...r.event.targetIds], objectRefs: [...r.event.objectRefs], parents: [...r.event.parents], signature: r.event.signature.slice() })) } },
    segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
    verifier: signer,
  })

  const sink = new MailRelationshipCredentialVaultSink({
    identityId, actorDeviceId: 'device-a',
    async nextActorSeq() { return records.length + 1 },
    async initialParents() { return records.length === 0 ? [] : ['event-1'] },
    async activeSegment() {
      const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(7), segmentKey, { identityId, selfGroupId: 'self-group-1', segmentId, sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z' }, signer)
      return { segmentId, segmentKey, keyWraps: [wrap] }
    },
    async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } },
    signer,
    committer: {
      async commitLocalMutation(input: any) {
        objects.set(input.objects[0].objectId, input.objects[0])
        records.push({ event: input.events[0], object: input.objects[0] } as any)
        return 'committed'
      },
    },
  })

  return { reader, sink }
}

describe('MailMediatorSubmissionTransport', () => {
  test('submit binds a relationship on first use, then polls submit-status-request to a completed accepted result', async () => {
    const { url, frontDoor, fetchImpl } = freshMailMediator(async record =>
      record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const })))
    const { reader, sink } = makeReaderSink(frontDoor.did)
    const transport = new MailMediatorSubmissionTransport({
      mediatorUrl: url, frontDoor, relationshipReader: reader, relationshipSink: sink, fetch: fetchImpl, pollIntervalMs: 5,
    })

    const result = await transport.submit({
      version: 1, identityId: frontDoor.did, deviceId: 'device-a', mailFrom: ADDRESS, rcptTo: ['a@example.com'],
      rawRfc5322: new Uint8Array([1, 2, 3]), submittedAt: '2026-01-01T00:00:00.000Z', signature: new Uint8Array([9]),
    })
    expect(result.status).toBe('accepted')
  })

  test('a rejected recipient is reported as temporary-failure with detail', async () => {
    const { url, frontDoor, fetchImpl } = freshMailMediator(async record =>
      record.rcptTo.map(recipient => ({ recipient, status: 'permanent-failure' as const, detail: 'no such user' })))
    const { reader, sink } = makeReaderSink(frontDoor.did)
    const transport = new MailMediatorSubmissionTransport({
      mediatorUrl: url, frontDoor, relationshipReader: reader, relationshipSink: sink, fetch: fetchImpl, pollIntervalMs: 5,
    })

    const result = await transport.submit({
      version: 1, identityId: frontDoor.did, deviceId: 'device-a', mailFrom: ADDRESS, rcptTo: ['a@example.com'],
      rawRfc5322: new Uint8Array([1, 2, 3]), submittedAt: '2026-01-01T00:00:00.000Z', signature: new Uint8Array([9]),
    })
    expect(result.status).toBe('temporary-failure')
    expect(result.detail).toContain('a@example.com')
    expect(result.detail).toContain('no such user')
  })

  test('resubmitting identical content reuses the same idempotency key (no duplicate dispatch)', async () => {
    let dispatchCount = 0
    const { url, frontDoor, fetchImpl } = freshMailMediator(async record => {
      dispatchCount++
      return record.rcptTo.map(recipient => ({ recipient, status: 'accepted' as const }))
    })
    const { reader, sink } = makeReaderSink(frontDoor.did)
    const transport = new MailMediatorSubmissionTransport({
      mediatorUrl: url, frontDoor, relationshipReader: reader, relationshipSink: sink, fetch: fetchImpl, pollIntervalMs: 5,
    })
    const request = {
      version: 1 as const, identityId: frontDoor.did, deviceId: 'device-a', mailFrom: ADDRESS, rcptTo: ['a@example.com'],
      rawRfc5322: new Uint8Array([1, 2, 3]), submittedAt: '2026-01-01T00:00:00.000Z', signature: new Uint8Array([9]),
    }
    await transport.submit(request)
    await transport.submit({ ...request, submittedAt: '2026-01-01T01:00:00.000Z' })
    expect(dispatchCount).toBe(1)
  })
})
