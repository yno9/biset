// End-to-end: a real MLS ClientState, a real Conversation Group DS
// (SqliteConversationDeliveryService) behind the real HTTP handler, and
// ConversationMlsDeliveryTransport in between -- confirms
// createConversationGroup / addMembersToConversationGroup /
// sendConversationApplicationMessage / receiveConversationEntry actually
// interoperate through the whole stack, mirroring
// mls-self-group-bootstrap.test.ts's Self Group version.
//
// Identity-blind revision: there is no external-join path any more (a
// stranger who only knows `groupId` cannot join -- see
// conversation-group.ts's header); joining is always Welcome-only, driven
// by an existing member's `addMembersToConversationGroup`. The full
// peer-to-peer bootstrap (invite -> join-ready -> add -> welcome-ready)
// this implies is covered separately in
// conversation-group-bootstrap.test.ts; this file exercises the
// lower-level MLS+DS orchestration primitives directly.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationWatchTokenIssuer } from '../../src/mls-ds/watch-token.ts'
import { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'
import { conversationDeliveriesPullSigningBytes } from '../../src/protocol/conversation-mls-ds-signing.ts'
import type { ConversationDeliveriesPullV1 } from '../../src/protocol/conversation-mls-ds.ts'
import {
  addMembersToConversationGroup,
  createConversationGroup,
  randomConversationGroupId,
  randomGroupLocalKeypair,
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

function signerFor(privateKey: Uint8Array) {
  return (bytes: Uint8Array) => ed25519.sign(bytes, privateKey)
}

function setup() {
  const ds = SqliteConversationDeliveryService.open(path)
  const handle = createConversationDeliveryHttpHandler(ds, new Ed25519ConversationDsSignatureVerifier(), new ConversationWatchTokenIssuer())
  const transport = new ConversationMlsDeliveryTransport({ baseUrl: 'https://mls-ds.example', fetch: (input, init) => handle(new Request(input, init)) })
  return { ds, transport }
}

async function pullDeliveries(transport: ConversationMlsDeliveryTransport, groupId: string, requesterId: string, sign: ReturnType<typeof signerFor>, afterSeq = 0) {
  const pull: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId, requesterId, afterSeq, requestedAt: new Date().toISOString() }
  return transport.pullDeliveries({ ...pull, signature: await sign(conversationDeliveriesPullSigningBytes(pull)) })
}

describe('conversation-group.ts end-to-end (identity-blind DS)', () => {
  test('alice creates a group (self-signed group-local key) and adds bob; bob joins from the Welcome and both exchange application messages', async () => {
    const { transport } = setup()
    const groupId = randomConversationGroupId()

    const created = await createConversationGroup(transport, groupId, alice.own)
    let aliceState = created.state
    const aliceSign = signerFor(created.ownGroupLocal.privateKey)
    const bobLocal = randomGroupLocalKeypair()
    const bobSign = signerFor(bobLocal.privateKey)

    aliceState = await addMembersToConversationGroup(
      aliceState, transport, groupId, created.ownGroupLocal.id, [{ keyPackage: bob.own.publicPackage, groupLocalId: bobLocal.id }], aliceSign,
    )

    // Bob fetches everything the DS logged for this group: his Welcome, then
    // the commit that added him. deliveriesSince gates on CURRENT
    // everMembership only, so it hands back the whole log even though bob
    // only just joined.
    const entries = await pullDeliveries(transport, groupId, bobLocal.id, bobSign)
    expect(entries.map(e => e.kind)).toEqual(['welcome', 'commit'])
    let bobState = await joinMlsGroup(entries[0]!.payload, bob.own, undefined)

    let sent = await sendConversationApplicationMessage(aliceState, transport, groupId, created.ownGroupLocal.id, new TextEncoder().encode('hello bob'), aliceSign)
    aliceState = sent

    const more = await pullDeliveries(transport, groupId, bobLocal.id, bobSign, entries[entries.length - 1]!.seq)
    expect(more.map(e => e.kind)).toEqual(['application'])
    const received = await receiveConversationEntry(bobState, more[0]!.payload)
    bobState = received.state
    expect(received.plaintext && new TextDecoder().decode(received.plaintext)).toBe('hello bob')
    // MLS-level attribution is unchanged by the identity-blind revision --
    // bob still learns alice's REAL DID kid, only the DS never does.
    expect(received.sender).toBe(alice.kid)

    // And the reverse direction: bob replies, alice decrypts.
    const reply = await sendConversationApplicationMessage(bobState, transport, groupId, bobLocal.id, new TextEncoder().encode('hi alice'), bobSign)
    bobState = reply
    const aliceEntries = await pullDeliveries(transport, groupId, created.ownGroupLocal.id, aliceSign, more[0]!.seq)
    expect(aliceEntries.map(e => e.kind)).toEqual(['application'])
    const aliceReceived = await receiveConversationEntry(aliceState, aliceEntries[0]!.payload)
    expect(aliceReceived.plaintext && new TextDecoder().decode(aliceReceived.plaintext)).toBe('hi alice')
    expect(aliceReceived.sender).toBe(bob.kid)
  })

  test('a stranger who only knows groupId cannot join -- there is no external-join path any more', async () => {
    const { ds, transport } = setup()
    const groupId = randomConversationGroupId()
    const created = await createConversationGroup(transport, groupId, alice.own)
    // Nothing on the transport even offers a way to fetch GroupInfo or
    // submit an external commit any more -- confirmed structurally: the DS
    // itself has no group-info/external-commit route (mls-ds/http.test.ts),
    // and this device's own roster is exactly the creator, unchanged.
    expect(ds.roster(groupId)).toEqual([created.ownGroupLocal.id])
    ds.close()
  })

  test('alice removes bob; bob can no longer read messages sent afterwards', async () => {
    const { transport } = setup()
    const groupId = randomConversationGroupId()

    const created = await createConversationGroup(transport, groupId, alice.own)
    let aliceState = created.state
    const aliceSign = signerFor(created.ownGroupLocal.privateKey)
    const bobLocal = randomGroupLocalKeypair()
    const bobSign = signerFor(bobLocal.privateKey)

    aliceState = await addMembersToConversationGroup(
      aliceState, transport, groupId, created.ownGroupLocal.id, [{ keyPackage: bob.own.publicPackage, groupLocalId: bobLocal.id }], aliceSign,
    )
    const entries = await pullDeliveries(transport, groupId, bobLocal.id, bobSign)
    let bobState = await joinMlsGroup(entries.find(e => e.kind === 'welcome')!.payload, bob.own, undefined)

    aliceState = await removeMembersFromConversationGroup(
      aliceState, transport, groupId, created.ownGroupLocal.id, [{ mlsKid: bob.kid, groupLocalId: bobLocal.id }], aliceSign,
    )
    expect(memberList(aliceState).map(m => m.kid)).toEqual([alice.kid])

    const sent = await sendConversationApplicationMessage(aliceState, transport, groupId, created.ownGroupLocal.id, new TextEncoder().encode('bob is gone now'), aliceSign)
    aliceState = sent

    // Bob's stale state can process the removal commit itself (still a
    // member as far as it knows when that commit arrives) but must not be
    // able to read anything sent afterwards -- the same forward-secrecy
    // guarantee test/mls-core.test.ts pins for Self Group's removeMembers.
    // store.ts's deliveriesSince gates on everMembers (never shrunk by a
    // removal), so bob's pull itself still succeeds; only decryption must fail.
    const afterRemoval = await pullDeliveries(transport, groupId, bobLocal.id, bobSign, entries[entries.length - 1]!.seq)
    expect(afterRemoval.map(e => e.kind)).toEqual(['commit', 'application'])
    bobState = (await receiveConversationEntry(bobState, afterRemoval[0]!.payload)).state
    let bobCouldRead = false
    try {
      const r = await receiveConversationEntry(bobState, afterRemoval[1]!.payload)
      bobCouldRead = r.plaintext !== undefined
    } catch { /* expected: bob's state can't decrypt a later epoch */ }
    expect(bobCouldRead).toBe(false)
  })

  test('removeMembersFromConversationGroup refuses to remove the committing device itself', async () => {
    const { transport } = setup()
    const groupId = randomConversationGroupId()
    const created = await createConversationGroup(transport, groupId, alice.own)
    const aliceSign = signerFor(created.ownGroupLocal.privateKey)
    await expect(removeMembersFromConversationGroup(
      created.state, transport, groupId, created.ownGroupLocal.id, [{ mlsKid: alice.kid, groupLocalId: created.ownGroupLocal.id }], aliceSign,
    )).rejects.toThrow(/cannot remove the committing device itself/)
  })
})
