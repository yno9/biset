// End-to-end: a real MLS ClientState, a real Conversation Group DS
// (SqliteConversationDeliveryService) behind the real HTTP handler, and
// ConversationMlsDeliveryTransport in between -- confirms
// createConversationGroup / addMembersToConversationGroup /
// sendConversationApplicationMessage / receiveConversationEntry actually
// interoperate through the whole stack, mirroring
// mls-self-group-bootstrap.test.ts's Self Group version.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'
import { conversationDeliveriesPullSigningBytes, conversationGroupInfoPullSigningBytes } from '../../src/protocol/conversation-mls-ds-signing.ts'
import type { ConversationDeliveriesPullV1, ConversationGroupInfoPullV1 } from '../../src/protocol/conversation-mls-ds.ts'
import {
  addMembersToConversationGroup,
  createConversationGroup,
  joinConversationGroupExternally,
  randomConversationGroupId,
  receiveConversationEntry,
  removeMembersFromConversationGroup,
  sendConversationApplicationMessage,
} from '../../src/mls/conversation-group.ts'
import { joinMlsGroup, memberList } from '../../src/mls/group.ts'
import type { OwnKeyPackage } from '../../src/mls/group.ts'
import { mlsDeviceFixture } from '../protocol/support/mls-device-fixture.ts'

const path = `/tmp/biset-conversation-group-e2e-${process.pid}-${Date.now()}.sqlite`
const alice = await mlsDeviceFixture('did:web:alice.example')
const bob = await mlsDeviceFixture('did:web:bob.example')

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function signerFor(kp: OwnKeyPackage) {
  return (bytes: Uint8Array) => ed25519.sign(bytes, kp.privatePackage.signaturePrivateKey)
}

function setup() {
  const ds = SqliteConversationDeliveryService.open(path)
  const verifier = new Ed25519ConversationDsSignatureVerifier({
    async resolveEd25519PublicKey(kid) {
      if (kid === alice.kid) return alice.own.publicPackage.leafNode.signaturePublicKey
      if (kid === bob.kid) return bob.own.publicPackage.leafNode.signaturePublicKey
      return undefined
    },
  })
  const handle = createConversationDeliveryHttpHandler(ds, verifier)
  const transport = new ConversationMlsDeliveryTransport({ baseUrl: 'https://mls-ds.example', deviceCredential: new Uint8Array([1]), fetch: (input, init) => handle(new Request(input, init)) })
  return { ds, transport }
}

async function pullDeliveries(transport: ConversationMlsDeliveryTransport, groupId: string, requesterKid: string, sign: ReturnType<typeof signerFor>, afterSeq = 0) {
  const pull: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId, requesterKid, afterSeq, requestedAt: new Date().toISOString() }
  return transport.pullDeliveries({ ...pull, signature: await sign(conversationDeliveriesPullSigningBytes(pull)) })
}

describe('conversation-group.ts end-to-end', () => {
  test('alice creates a group and adds bob; bob joins from the Welcome and both exchange application messages', async () => {
    const { transport } = setup()
    const groupId = randomConversationGroupId()
    const aliceSign = signerFor(alice.own)
    const bobSign = signerFor(bob.own)

    let aliceState = await createConversationGroup(transport, groupId, alice.kid, alice.own, aliceSign)
    aliceState = await addMembersToConversationGroup(aliceState, transport, groupId, alice.kid, [bob.own.publicPackage], [bob.kid], aliceSign)

    // Bob fetches everything the DS logged for this group: createConversationGroup's
    // own GroupInfo-publishing rekey commit, then the Welcome and commit that
    // added him -- deliveriesSince gates on CURRENT everMembership only, so
    // it hands back the whole log, including entries from before bob joined.
    // The DS admitted him into everMembers the moment alice's add commit
    // landed (store.ts's submitCommit), so this pull needs no prior join
    // step of its own.
    const entries = await pullDeliveries(transport, groupId, bob.kid, bobSign)
    expect(entries.map(e => e.kind)).toEqual(['commit', 'welcome', 'commit'])
    const welcomeEntry = entries.find(e => e.kind === 'welcome')!
    let bobState = await joinMlsGroup(welcomeEntry.payload, bob.own, undefined)

    let sent = await sendConversationApplicationMessage(aliceState, transport, groupId, alice.kid, new TextEncoder().encode('hello bob'), aliceSign)
    aliceState = sent

    const more = await pullDeliveries(transport, groupId, bob.kid, bobSign, entries[entries.length - 1]!.seq)
    expect(more.map(e => e.kind)).toEqual(['application'])
    const received = await receiveConversationEntry(bobState, more[0]!.payload)
    bobState = received.state
    expect(received.plaintext && new TextDecoder().decode(received.plaintext)).toBe('hello bob')

    // And the reverse direction: bob replies, alice decrypts.
    const reply = await sendConversationApplicationMessage(bobState, transport, groupId, bob.kid, new TextEncoder().encode('hi alice'), bobSign)
    bobState = reply
    const aliceEntries = await pullDeliveries(transport, groupId, alice.kid, aliceSign, more[0]!.seq)
    expect(aliceEntries.map(e => e.kind)).toEqual(['application'])
    const aliceReceived = await receiveConversationEntry(aliceState, aliceEntries[0]!.payload)
    expect(aliceReceived.plaintext && new TextDecoder().decode(aliceReceived.plaintext)).toBe('hi alice')
  })

  test('bob joins externally right after alice creates the group -- no add, no other device online', async () => {
    const { transport } = setup()
    const groupId = randomConversationGroupId()
    const aliceSign = signerFor(alice.own)
    const bobSign = signerFor(bob.own)
    await createConversationGroup(transport, groupId, alice.kid, alice.own, aliceSign)

    const pull: Omit<ConversationGroupInfoPullV1, 'signature'> = { version: 1, groupId, requesterKid: bob.kid, requestedAt: new Date().toISOString() }
    const { groupInfo } = await transport.pullGroupInfo({ ...pull, signature: await bobSign(conversationGroupInfoPullSigningBytes(pull)) })
    expect(groupInfo).toBeDefined()

    const bobState = await joinConversationGroupExternally(transport, groupId, bob.kid, groupInfo!, bob.own, bobSign)
    expect(bobState).toBeDefined()
    expect(bobState!.ratchetTree.filter(n => n?.nodeType === 'leaf').length).toBe(2)
  })

  test('alice removes bob; bob can no longer read messages sent afterwards', async () => {
    const { transport } = setup()
    const groupId = randomConversationGroupId()
    const aliceSign = signerFor(alice.own)
    const bobSign = signerFor(bob.own)

    let aliceState = await createConversationGroup(transport, groupId, alice.kid, alice.own, aliceSign)
    aliceState = await addMembersToConversationGroup(aliceState, transport, groupId, alice.kid, [bob.own.publicPackage], [bob.kid], aliceSign)
    const entries = await pullDeliveries(transport, groupId, bob.kid, bobSign)
    let bobState = await joinMlsGroup(entries.find(e => e.kind === 'welcome')!.payload, bob.own, undefined)

    aliceState = await removeMembersFromConversationGroup(aliceState, transport, groupId, alice.kid, [bob.kid], aliceSign)
    expect(memberList(aliceState).map(m => m.kid)).toEqual([alice.kid])

    const sent = await sendConversationApplicationMessage(aliceState, transport, groupId, alice.kid, new TextEncoder().encode('bob is gone now'), aliceSign)
    aliceState = sent

    // Bob's stale state can process the removal commit itself (still a
    // member as far as it knows when that commit arrives) but must not be
    // able to read anything sent afterwards -- the same forward-secrecy
    // guarantee test/mls-core.test.ts pins for Self Group's removeMembers.
    // store.ts's deliveriesSince gates on everMembers (never shrunk by a
    // removal), so bob's pull itself still succeeds; only decryption must fail.
    const afterRemoval = await pullDeliveries(transport, groupId, bob.kid, bobSign, entries[entries.length - 1]!.seq)
    expect(afterRemoval.map(e => e.kind)).toEqual(['commit', 'application'])
    bobState = (await receiveConversationEntry(bobState, afterRemoval[0]!.payload)).state
    let bobCouldRead = false
    try {
      const r = await receiveConversationEntry(bobState, afterRemoval[1]!.payload)
      bobCouldRead = r.plaintext !== undefined
    } catch { /* expected: bob's state can't decrypt a later epoch */ }
    expect(bobCouldRead).toBe(false)
  })
})
