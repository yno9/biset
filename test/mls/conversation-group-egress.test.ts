// End-to-end: sendConversationTextMessage against a real 2-member group and
// a real DS -- confirms the composed MimiContent actually decrypts on the
// other side (via receiveConversationEntry, the same primitive
// conversation-group-sync.ts uses) and that its content-addressed
// messageId matches what the OWN-copy projection
// (mimi-content-projector.ts) would file it under, so a sender's own Vault
// write and a recipient's synced copy agree on the same id.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationWatchTokenIssuer } from '../../src/mls-ds/watch-token.ts'
import { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'
import { addMembersToConversationGroup, createConversationGroup, randomGroupLocalKeypair, receiveConversationEntry } from '../../src/mls/conversation-group.ts'
import { sendConversationTextMessage } from '../../src/mls/conversation-group-egress.ts'
import { joinMlsGroup } from '../../src/mls/group.ts'
import { computeMimiMessageId, decodeMimiContent } from '../../src/mls/mimi-content.ts'
import { messageIdToEmailId, projectMimiConversationMessage } from '../../src/mls/mimi-content-projector.ts'
import { createSegmentKey, decryptVaultObject } from '../../src/vault/objects.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { mlsDeviceFixture } from '../protocol/support/mls-device-fixture.ts'

const path = `/tmp/biset-conversation-group-egress-e2e-${process.pid}-${Date.now()}.sqlite`
const alice = await mlsDeviceFixture('did:web:alice.example')
const bob = await mlsDeviceFixture('did:web:bob.example')

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) { try { rmSync(`${path}${suffix}`) } catch {} }
})

const signer: VaultEventSigner = {
  deviceId: alice.kid,
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === alice.kid && equalBytes(signature, await this.sign(bytes)) },
}

describe('sendConversationTextMessage', () => {
  test('composes a MimiContent, submits it, and bob decrypts the identical content -- both sides agree on messageId', async () => {
    const ds = SqliteConversationDeliveryService.open(path)
    const handle = createConversationDeliveryHttpHandler(ds, new Ed25519ConversationDsSignatureVerifier(), new ConversationWatchTokenIssuer())
    const transport = new ConversationMlsDeliveryTransport({ baseUrl: 'https://mls-ds.example', fetch: (input, init) => handle(new Request(input, init)) })
    const groupId = 'group-egress-1'

    const created = await createConversationGroup(transport, groupId, alice.own)
    let aliceState = created.state
    const aliceSign = (bytes: Uint8Array) => ed25519.sign(bytes, created.ownGroupLocal.privateKey)
    const bobLocal = randomGroupLocalKeypair()

    aliceState = await addMembersToConversationGroup(
      aliceState, transport, groupId, created.ownGroupLocal.id, [{ keyPackage: bob.own.publicPackage, groupLocalId: bobLocal.id }], aliceSign,
    )
    const welcomeEntry = ds.deliveriesSince(groupId, bobLocal.id, 0)!.find(e => e.kind === 'welcome')!
    const bobState = await joinMlsGroup(welcomeEntry.payload, bob.own, undefined)
    const beforeSend = ds.deliveriesSince(groupId, bobLocal.id, 0)!.length

    const sent = await sendConversationTextMessage({ state: aliceState, transport, groupId, deviceKid: alice.kid, senderId: created.ownGroupLocal.id, text: 'hello from egress', sign: aliceSign })
    aliceState = sent.state
    expect(sent.otherMembers).toEqual(['did:web:bob.example'])

    // Alice's own-copy Vault write, built from what sendConversationTextMessage returned.
    const segmentKey = createSegmentKey()
    const ownCopy = await projectMimiConversationMessage({
      content: sent.content, messageId: sent.messageId, groupId, senderDid: alice.kid, otherMembers: sent.otherMembers, receivedAt: '2026-08-31T00:00:00.000Z',
    }, { identityId: 'did:web:alice.example', actorDeviceId: alice.kid, actorSeq: 1, parents: [], segmentId: 'segment-1', segmentKey, createdAt: '2026-08-31T00:00:00.000Z' }, signer)
    expect(ownCopy.events[0]!.kind).toBe('message.add')

    // Bob's independently-decrypted copy must land on the SAME id.
    const entries = ds.deliveriesSince(groupId, bobLocal.id, beforeSend)!
    const applicationEntry = entries.find(e => e.kind === 'application')!
    const received = await receiveConversationEntry(bobState, applicationEntry.payload)
    expect(received.plaintext).toBeDefined()
    expect(received.sender).toBe(alice.kid)
    const bobContent = decodeMimiContent(received.plaintext!)
    const bobMessageId = await computeMimiMessageId(bobContent.extensions.senderUri!, bobContent.extensions.roomUri!, received.plaintext!, bobContent.salt)
    expect(bobMessageId).toEqual(sent.messageId)
    expect(messageIdToEmailId(bobMessageId)).toBe(messageIdToEmailId(sent.messageId))

    const decryptedMeta = JSON.parse(new TextDecoder().decode(await decryptVaultObject(segmentKey, ownCopy.objects[0]!))) as { payload: { email: { id: string } } }
    expect(decryptedMeta.payload.email.id).toBe(messageIdToEmailId(bobMessageId))

    ds.close()
  })
})
