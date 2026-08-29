// ensureMailRelationship, driven against a real in-process Mail Mediator
// (same "fetch dispatches straight into the handler" pattern as
// test/mail-mediator-client.test.ts) with an in-memory Vault
// reader/sink pair (same pattern as
// test/vault/mail-relationship-credential-{reader,sink}.test.ts).
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { createMailMediator } from '../../src/mail-mediator/server.ts'
import type { DidCommSender } from '../../src/didcomm/mediator-transport.ts'
import { ensureMailRelationship } from '../../src/identity/mail-relationship.ts'
import { MailRelationshipCredentialReader } from '../../src/vault/mail-relationship-credential-reader.ts'
import { MailRelationshipCredentialVaultSink } from '../../src/vault/mail-relationship-credential-sink.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { equalBytes } from '../../src/protocol/canonical.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'

const segmentId = 'segment-1'
const segmentKey = createSegmentKey()
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}
const ADDRESS = 'y@biset.md'

function freshMailMediator() {
  const url = `https://mail-mediator-${crypto.randomUUID()}.test.example`
  const mediatorIdentity = generatePeerIdentity({ uri: url, accept: ['didcomm/v2'] })
  const frontDoorPeer = generatePeerIdentity()
  const { handle } = createMailMediator({
    mediator: mediatorIdentity,
    resolveMailOperationalKid: async kid => (kid === frontDoorPeer.xKid ? { address: ADDRESS, publicKey: frontDoorPeer.xPub } : null),
    submitOutbound: async () => [],
  })
  const fetchImpl: typeof fetch = async (input, init) => {
    const reqUrl = new URL(String(input))
    const res = await handle(new Request(reqUrl, init), reqUrl)
    return res ?? new Response('not found', { status: 404 })
  }
  return { url, frontDoor: { did: frontDoorPeer.did, xKid: frontDoorPeer.xKid, xPriv: frontDoorPeer.xPriv } satisfies DidCommSender, fetchImpl }
}

/** A trivially in-memory reader/sink pair sharing one array of committed
 * records -- storing through the sink makes it visible to the reader,
 * exactly the property ensureMailRelationship's own second call relies on. */
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
      // The sink already built the encrypted object/event pair -- this
      // just records what it committed so the reader (sharing `records`
      // and `objects` above) can see it on a later call.
      async commitLocalMutation(input: any) {
        objects.set(input.objects[0].objectId, input.objects[0])
        records.push({ event: input.events[0], object: input.objects[0] } as any)
        return 'committed'
      },
    },
  })

  return { reader, sink }
}

describe('ensureMailRelationship', () => {
  test('mints a fresh relationship and binds it when none exists yet', async () => {
    const { url, frontDoor, fetchImpl } = freshMailMediator()
    const { reader, sink } = makeReaderSink(frontDoor.did)

    const credential = await ensureMailRelationship(reader, sink, frontDoor, ADDRESS, url, fetchImpl)
    expect(credential.mediatorUrl).toBe(url)
    expect(credential.address).toBe(ADDRESS)
    expect(credential.relationshipDid.startsWith('did:peer:2.')).toBe(true)
  })

  test('a second call reuses the already-bound relationship without re-binding', async () => {
    const { url, frontDoor, fetchImpl } = freshMailMediator()
    const { reader, sink } = makeReaderSink(frontDoor.did)

    const first = await ensureMailRelationship(reader, sink, frontDoor, ADDRESS, url, fetchImpl)
    const second = await ensureMailRelationship(reader, sink, frontDoor, ADDRESS, url, fetchImpl)
    expect(second.relationshipDid).toBe(first.relationshipDid)
  })
})
