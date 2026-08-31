// Full peer-to-peer bootstrap: alice invites bob, bob publishes a KeyPackage
// under a fresh group-local id and tells alice it's ready, alice takes it
// and adds him, tells bob to pull -- then bob catches up via
// conversation-group-sync.ts and decrypts alice's first message. Exercises
// conversation-group-invite.ts's three message types end to end (built via
// the same buildPlaintext biset's other DIDComm messages use) and, most
// importantly, proves the property the whole identity-blind revision exists
// for: nothing DID-shaped ever reaches the DS at any step.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { buildPlaintext } from '../../src/didcomm/message.ts'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'
import { conversationKeyPackagePublishSigningBytes, conversationKeyPackageTakeSigningBytes } from '../../src/protocol/conversation-mls-ds-signing.ts'
import type { ConversationKeyPackagePublishV1, ConversationKeyPackageTakeV1 } from '../../src/protocol/conversation-mls-ds.ts'
import {
  CONVERSATION_GROUP_INVITE, CONVERSATION_GROUP_JOIN_READY, CONVERSATION_GROUP_WELCOME_READY,
  conversationGroupInviteBodyOf, conversationGroupJoinReadyBodyOf, conversationGroupWelcomeReadyBodyOf,
} from '../../src/mls/conversation-group-invite.ts'
import { addMembersToConversationGroup, createConversationGroup, randomConversationGroupId, randomGroupLocalKeypair } from '../../src/mls/conversation-group.ts'
import { syncConversationGroupDeliveries, type ConversationGroupVaultRecord } from '../../src/mls/conversation-group-sync.ts'
import type { ConversationGroupRosterEntry, MlsConversationGroupStateStore } from '../../src/mls/conversation-group-store.ts'
import { decodeKeyPackage, encodeKeyPackage, joinMlsGroup, type ClientState } from '../../src/mls/group.ts'
import { encodeMimiContent, mimiRoomUri, DISPOSITION_RENDER, type MimiContent } from '../../src/mls/mimi-content.ts'
import { sendConversationApplicationMessage } from '../../src/mls/conversation-group.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { mlsDeviceFixture } from '../protocol/support/mls-device-fixture.ts'

const bobIdentityId = 'did:web:bob.example'
const alice = await mlsDeviceFixture('did:web:alice.example')
const bob = await mlsDeviceFixture(bobIdentityId)

const signer: VaultEventSigner = {
  deviceId: bob.kid,
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === bob.kid && equalBytes(signature, await this.sign(bytes)) },
}

const path = `/tmp/biset-conversation-group-bootstrap-${process.pid}-${Date.now()}.sqlite`
afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) { try { rmSync(`${path}${suffix}`) } catch {} }
})

function memoryStateStore(): MlsConversationGroupStateStore {
  const rows = new Map<string, { state: ClientState; lastSeenSeq: number; ownGroupLocalPrivateKey: Uint8Array; roster: ConversationGroupRosterEntry[] }>()
  return {
    async save(groupId, state, lastSeenSeq, ownGroupLocalPrivateKey, roster) { rows.set(groupId, { state, lastSeenSeq, ownGroupLocalPrivateKey, roster }) },
    async load(groupId) { return rows.get(groupId) },
    async listGroupIds() { return [...rows.keys()] },
  }
}

describe('Conversation Group peer-to-peer bootstrap (identity-blind DS)', () => {
  test('invite -> join-ready -> add -> welcome-ready -> sync, with nothing DID-shaped ever reaching the DS', async () => {
    const ds = SqliteConversationDeliveryService.open(path)
    const handle = createConversationDeliveryHttpHandler(ds, new Ed25519ConversationDsSignatureVerifier())
    const transport = new ConversationMlsDeliveryTransport({ baseUrl: 'https://mls-ds.example', fetch: (input, init) => handle(new Request(input, init)) })

    // --- Step 1: alice creates the group (self-signed, zero DID touches the DS) ---
    const groupId = randomConversationGroupId()
    const created = await createConversationGroup(transport, groupId, alice.own)
    let aliceState = created.state
    const aliceSign = (bytes: Uint8Array) => ed25519.sign(bytes, created.ownGroupLocal.privateKey)

    // --- Step 2: alice invites bob (1:1 DIDComm plaintext, DS never sees this) ---
    const invitePlaintext = buildPlaintext(CONVERSATION_GROUP_INVITE, { groupId, ds: 'did:web:mls-ds.example' })
    const inviteBody = conversationGroupInviteBodyOf(invitePlaintext)
    expect(inviteBody).toEqual({ groupId, ds: 'did:web:mls-ds.example' })

    // --- Step 3: bob generates a fresh group-local id + MLS KeyPackage, publishes it ---
    const bobLocal = randomGroupLocalKeypair()
    const bobSign = (bytes: Uint8Array) => ed25519.sign(bytes, bobLocal.privateKey)
    const publish: Omit<ConversationKeyPackagePublishV1, 'signature'> = {
      version: 1, id: bobLocal.id, packages: [encodeKeyPackage(bob.own.publicPackage)], publishedAt: new Date().toISOString(),
    }
    await transport.publishKeyPackages({ ...publish, signature: bobSign(conversationKeyPackagePublishSigningBytes(publish)) })

    // --- Step 4: bob tells alice "take my KeyPackage under this id" ---
    const joinReadyPlaintext = buildPlaintext(CONVERSATION_GROUP_JOIN_READY, { groupId, groupLocalId: bobLocal.id })
    const joinReadyBody = conversationGroupJoinReadyBodyOf(joinReadyPlaintext)
    expect(joinReadyBody).toEqual({ groupId, groupLocalId: bobLocal.id })

    // --- Step 5: alice takes it and adds bob ---
    const take: Omit<ConversationKeyPackageTakeV1, 'signature'> = { version: 1, requesterId: created.ownGroupLocal.id, targetId: joinReadyBody!.groupLocalId, requestedAt: new Date().toISOString() }
    const taken = await transport.takeKeyPackage({ ...take, signature: aliceSign(conversationKeyPackageTakeSigningBytes(take)) })
    expect(taken).toBeDefined()
    const bobKeyPackage = decodeKeyPackage(taken!.keyPackage)
    aliceState = await addMembersToConversationGroup(
      aliceState, transport, groupId, created.ownGroupLocal.id, [{ keyPackage: bobKeyPackage, groupLocalId: joinReadyBody!.groupLocalId }], aliceSign,
    )

    // --- Step 6: alice tells bob "you're in, pull now" ---
    const welcomeReadyPlaintext = buildPlaintext(CONVERSATION_GROUP_WELCOME_READY, { groupId })
    expect(conversationGroupWelcomeReadyBodyOf(welcomeReadyPlaintext)).toEqual({ groupId })

    // --- Step 7: bob pulls, consumes his Welcome, and saves his initial local state ---
    const initialEntries = await ds.deliveriesSince(groupId, bobLocal.id, 0)
    const welcomeEntry = initialEntries!.find(e => e.kind === 'welcome')!
    const bobState = await joinMlsGroup(welcomeEntry.payload, bob.own, undefined)
    const stateStore = memoryStateStore()
    await stateStore.save(groupId, bobState, 0, bobLocal.privateKey, [])

    // --- Step 8: alice sends a message; bob catches up via the ordinary sync loop ---
    const content: MimiContent = {
      salt: new Uint8Array(16).fill(5), replaces: null, topicId: new Uint8Array(0), expires: null, inReplyTo: null,
      extensions: { senderUri: alice.kid, roomUri: mimiRoomUri(groupId) },
      nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode('welcome to the group') } },
    }
    await sendConversationApplicationMessage(aliceState, transport, groupId, created.ownGroupLocal.id, encodeMimiContent(content), aliceSign)

    const committed: ConversationGroupVaultRecord[] = []
    let actorSeq = 1
    const result = await syncConversationGroupDeliveries(groupId, {
      stateStore, transport, sign: bobSign,
      identityId: bobIdentityId, actorDeviceId: bob.kid,
      async nextActorSeq() { return actorSeq++ },
      async initialParents() { return [] },
      async activeSegment() {
        const segmentKey = createSegmentKey()
        const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(9), segmentKey, {
          identityId: bobIdentityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: bob.kid, grantedAt: '2026-08-31T00:00:00.000Z',
        }, signer)
        return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] }
      },
      async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [] } },
      signer,
      async commitVaultRecord(record) { committed.push(record) },
    })
    expect(result.applied).toBe(1)
    expect(committed[0]!.events[0]!.kind).toBe('message.add')

    // --- The actual point of this test: the DS never saw anything DID-shaped ---
    for (const id of ds.roster(groupId)) {
      expect(id.startsWith('did:')).toBe(false)
      expect(id).not.toContain('#')
    }
    ds.close()
  })
})
