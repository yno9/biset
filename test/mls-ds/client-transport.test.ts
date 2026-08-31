// End-to-end: ConversationMlsDeliveryTransport (client) against
// createConversationDeliveryHttpHandler (mls-ds/http.ts), through the
// shared protocol/conversation-mls-ds-wire.ts encode/decode -- confirms the
// client and server sides of the wire actually agree, mirroring
// mls-delivery-client-transport.test.ts's Self Group version.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'
import {
  conversationCommitSubmitSigningBytes, conversationDeliveriesPullSigningBytes, conversationGroupCreateSigningBytes,
  conversationGroupInfoPullSigningBytes, conversationGroupsForPullSigningBytes, conversationKeyPackageCountPullSigningBytes,
  conversationKeyPackageDropSigningBytes, conversationKeyPackagePublishSigningBytes, conversationKeyPackageTakeSigningBytes,
  conversationMessageSubmitSigningBytes, conversationPendingRemovalsClearSigningBytes, conversationSelfRemoveSubmitSigningBytes,
} from '../../src/protocol/conversation-mls-ds-signing.ts'
import type {
  ConversationCommitSubmitV1, ConversationDeliveriesPullV1, ConversationGroupCreateV1, ConversationGroupInfoPullV1,
  ConversationGroupsForPullV1, ConversationKeyPackageCountPullV1, ConversationKeyPackageDropV1, ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1, ConversationMessageSubmitV1, ConversationPendingRemovalsClearV1, ConversationSelfRemoveSubmitV1,
} from '../../src/protocol/conversation-mls-ds.ts'

const path = `/tmp/biset-conversation-ds-client-${process.pid}-${Date.now()}.sqlite`
const groupId = 'group-1'
const aliceKey = ed25519.utils.randomSecretKey()
const alicePublicKey = ed25519.getPublicKey(aliceKey)
const aliceKid = 'did:web:alice.example#key-1'

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function setup() {
  const ds = SqliteConversationDeliveryService.open(path)
  const verifier = new Ed25519ConversationDsSignatureVerifier({ async resolveEd25519PublicKey(kid) { return kid === aliceKid ? alicePublicKey : undefined } })
  const handle = createConversationDeliveryHttpHandler(ds, verifier)
  const transport = new ConversationMlsDeliveryTransport({ baseUrl: 'https://mls-ds.example', deviceCredential: new Uint8Array([1]), fetch: (input, init) => handle(new Request(input, init)) })
  return { ds, transport }
}

describe('ConversationMlsDeliveryTransport <-> Conversation Group DS HTTP handler', () => {
  test('createGroup then submitCommit round-trip, and a stale-epoch retry surfaces as ok:false, not a throw', async () => {
    const { ds, transport } = setup()
    const creation: Omit<ConversationGroupCreateV1, 'signature'> = { version: 1, groupId, creatorKid: aliceKid, roster: [], createdAt: '2026-08-31T00:00:00.000Z' }
    const roster = await transport.createGroup({ ...creation, signature: ed25519.sign(conversationGroupCreateSigningBytes(creation), aliceKey) })
    expect(roster).toEqual([aliceKid])

    const commit: Omit<ConversationCommitSubmitV1, 'signature'> = { version: 1, groupId, senderKid: aliceKid, epoch: '0', commit: new Uint8Array([1]), roster: [aliceKid], submittedAt: '2026-08-31T00:00:01.000Z' }
    const accepted = await transport.submitCommit({ ...commit, signature: ed25519.sign(conversationCommitSubmitSigningBytes(commit), aliceKey) })
    expect(accepted).toEqual({ ok: true, roster: [aliceKid] })

    const stale = await transport.submitCommit({ ...commit, signature: ed25519.sign(conversationCommitSubmitSigningBytes(commit), aliceKey) })
    expect(stale).toEqual({ ok: false, reason: 'epoch-conflict', epoch: '1' })
    ds.close()
  })

  test('pullGroupInfo decodes the answer the DS encoded', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, aliceKid, [])
    ds.submitCommit(groupId, aliceKid, '0', new Uint8Array([1]), [aliceKid], undefined, undefined, new Uint8Array([9]))
    const pull: Omit<ConversationGroupInfoPullV1, 'signature'> = { version: 1, groupId, requesterKid: aliceKid, requestedAt: '2026-08-31T00:00:00.000Z' }
    const answer = await transport.pullGroupInfo({ ...pull, signature: ed25519.sign(conversationGroupInfoPullSigningBytes(pull), aliceKey) })
    expect(answer).toEqual({ groupInfo: new Uint8Array([9]), pendingRemovals: [] })
    ds.close()
  })

  test('publishKeyPackages / takeKeyPackage / dropKeyPackages / keyPackageCount round-trip binary payloads', async () => {
    const { ds, transport } = setup()
    const publish: Omit<ConversationKeyPackagePublishV1, 'signature'> = { version: 1, kid: aliceKid, packages: [new Uint8Array([1, 2]), new Uint8Array([3])], publishedAt: '2026-08-31T00:00:00.000Z' }
    expect(await transport.publishKeyPackages({ ...publish, signature: ed25519.sign(conversationKeyPackagePublishSigningBytes(publish), aliceKey) })).toBe(2)

    const countPull: Omit<ConversationKeyPackageCountPullV1, 'signature'> = { version: 1, kid: aliceKid, requestedAt: '2026-08-31T00:00:01.000Z' }
    expect(await transport.keyPackageCount({ ...countPull, signature: ed25519.sign(conversationKeyPackageCountPullSigningBytes(countPull), aliceKey) })).toBe(2)

    const take: Omit<ConversationKeyPackageTakeV1, 'signature'> = { version: 1, requesterKid: aliceKid, targetKid: aliceKid, requestedAt: '2026-08-31T00:00:02.000Z' }
    const taken = await transport.takeKeyPackage({ ...take, signature: ed25519.sign(conversationKeyPackageTakeSigningBytes(take), aliceKey) })
    expect(taken).toEqual({ keyPackage: new Uint8Array([1, 2]) })

    const drop: Omit<ConversationKeyPackageDropV1, 'signature'> = { version: 1, kid: aliceKid, droppedAt: '2026-08-31T00:00:03.000Z' }
    await transport.dropKeyPackages({ ...drop, signature: ed25519.sign(conversationKeyPackageDropSigningBytes(drop), aliceKey) })
    expect(ds.keyPackageCount(aliceKid)).toBe(0)
    ds.close()
  })

  test('submitSelfRemove / clearPendingRemovals / pullDeliveries round-trip', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, aliceKid, [])
    ds.submitCommit(groupId, aliceKid, '0', new Uint8Array([1]), [aliceKid])

    const selfRemove: Omit<ConversationSelfRemoveSubmitV1, 'signature'> = { version: 1, groupId, senderKid: aliceKid, epoch: '1', proposal: new Uint8Array([5]), removedKid: aliceKid, submittedAt: '2026-08-31T00:00:00.000Z' }
    const removed = await transport.submitSelfRemove({ ...selfRemove, signature: ed25519.sign(conversationSelfRemoveSubmitSigningBytes(selfRemove), aliceKey) })
    expect(removed.ok).toBe(true)

    const clear: Omit<ConversationPendingRemovalsClearV1, 'signature'> = { version: 1, groupId, requesterKid: aliceKid, clearedKids: [aliceKid], clearedAt: '2026-08-31T00:00:01.000Z' }
    await transport.clearPendingRemovals({ ...clear, signature: ed25519.sign(conversationPendingRemovalsClearSigningBytes(clear), aliceKey) })
    expect(ds.groupInfoFor(groupId)?.pendingRemovals).toEqual([])

    const pull: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId, requesterKid: aliceKid, afterSeq: 0, requestedAt: '2026-08-31T00:00:02.000Z' }
    const entries = await transport.pullDeliveries({ ...pull, signature: ed25519.sign(conversationDeliveriesPullSigningBytes(pull), aliceKey) })
    expect(entries.map(e => ({ seq: e.seq, kind: e.kind }))).toEqual([{ seq: 1, kind: 'commit' }, { seq: 2, kind: 'proposal' }])
    ds.close()
  })

  test('groupsFor round-trips the epoch as a decimal string', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, aliceKid, [])
    const pull: Omit<ConversationGroupsForPullV1, 'signature'> = { version: 1, requesterKid: aliceKid, requestedAt: '2026-08-31T00:00:00.000Z' }
    expect(await transport.groupsFor({ ...pull, signature: ed25519.sign(conversationGroupsForPullSigningBytes(pull), aliceKey) })).toEqual([{ groupId, epoch: '0' }])
    ds.close()
  })

  test('submitMessage (no Self Group equivalent) round-trips application data', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, aliceKid, [])
    const submit: Omit<ConversationMessageSubmitV1, 'signature'> = { version: 1, groupId, senderKid: aliceKid, epoch: '0', privateMessage: new Uint8Array([4, 5, 6]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const accepted = await transport.submitMessage({ ...submit, signature: ed25519.sign(conversationMessageSubmitSigningBytes(submit), aliceKey) })
    expect(accepted.ok).toBe(true)
    expect(ds.deliveriesSince(groupId, aliceKid, 0).map(e => e.kind)).toEqual(['application'])
    ds.close()
  })
})
