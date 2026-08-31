import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import {
  clearConversationPendingRemovals, createConversationGroup, dropConversationKeyPackages, Ed25519ConversationDsSignatureVerifier,
  publishConversationKeyPackages, pullConversationDeliveries, pullConversationGroupInfo, pullConversationGroupsFor,
  pullConversationKeyPackageCount, submitConversationCommit, submitConversationExternalCommit, submitConversationMessage,
  submitConversationSelfRemove, takeConversationKeyPackage,
} from '../../src/mls-ds/authorizer.ts'
import {
  conversationCommitSubmitSigningBytes, conversationDeliveriesPullSigningBytes, conversationExternalCommitSubmitSigningBytes,
  conversationGroupCreateSigningBytes, conversationGroupInfoPullSigningBytes, conversationGroupsForPullSigningBytes,
  conversationKeyPackageCountPullSigningBytes, conversationKeyPackageDropSigningBytes, conversationKeyPackagePublishSigningBytes,
  conversationKeyPackageTakeSigningBytes, conversationMessageSubmitSigningBytes, conversationPendingRemovalsClearSigningBytes,
  conversationSelfRemoveSubmitSigningBytes,
} from '../../src/protocol/conversation-mls-ds-signing.ts'
import type {
  ConversationCommitSubmitV1, ConversationDeliveriesPullV1, ConversationExternalCommitSubmitV1, ConversationGroupCreateV1,
  ConversationGroupInfoPullV1, ConversationGroupsForPullV1, ConversationKeyPackageCountPullV1, ConversationKeyPackageDropV1,
  ConversationKeyPackagePublishV1, ConversationKeyPackageTakeV1, ConversationMessageSubmitV1, ConversationPendingRemovalsClearV1,
  ConversationSelfRemoveSubmitV1,
} from '../../src/protocol/conversation-mls-ds.ts'

const path = `/tmp/biset-conversation-ds-auth-${process.pid}-${Date.now()}.sqlite`
const groupId = 'group-1'
const aliceKey = ed25519.utils.randomSecretKey()
const alicePublicKey = ed25519.getPublicKey(aliceKey)
const bobKey = ed25519.utils.randomSecretKey()
const bobPublicKey = ed25519.getPublicKey(bobKey)
const strangerKey = ed25519.utils.randomSecretKey()
const aliceKid = 'did:web:alice.example#key-1'
const bobKid = 'did:web:bob.example#key-1'

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function verifier() {
  return new Ed25519ConversationDsSignatureVerifier({
    async resolveEd25519PublicKey(kid) {
      if (kid === aliceKid) return alicePublicKey
      if (kid === bobKid) return bobPublicKey
      return undefined
    },
  })
}

function open(): SqliteConversationDeliveryService { return SqliteConversationDeliveryService.open(path) }

describe('Conversation Group DS authorizer (signature verification over the sender\'s own device key, no identityId)', () => {
  test('createConversationGroup accepts a validly self-signed genesis, rejects a forged one', async () => {
    const ds = open()
    const unsigned: Omit<ConversationGroupCreateV1, 'signature'> = { version: 1, groupId, creatorKid: aliceKid, roster: [], createdAt: '2026-08-31T00:00:00.000Z' }
    const valid = { ...unsigned, signature: ed25519.sign(conversationGroupCreateSigningBytes(unsigned), aliceKey) }
    expect(await createConversationGroup(ds, verifier(), valid)).toEqual({ ok: true, roster: [aliceKid] })

    const forged = { ...unsigned, groupId: 'group-2', signature: ed25519.sign(conversationGroupCreateSigningBytes(unsigned), strangerKey) }
    expect(await createConversationGroup(ds, verifier(), forged)).toEqual({ ok: false })
    ds.close()
  })

  test('submitConversationCommit rejects a forged submission without touching DS state', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceKid, [])
    const unsigned: Omit<ConversationCommitSubmitV1, 'signature'> = { version: 1, groupId, senderKid: aliceKid, epoch: '0', commit: new Uint8Array([1]), roster: [aliceKid], submittedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationCommitSubmitSigningBytes(unsigned), strangerKey) }
    expect(await submitConversationCommit(ds, verifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(conversationCommitSubmitSigningBytes(unsigned), aliceKey) }
    expect((await submitConversationCommit(ds, verifier(), valid)).ok).toBe(true)
    ds.close()
  })

  test('submitConversationExternalCommit requires the sender\'s own signature, with no identity gate on top', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceKid, [])
    ds.submitCommit(groupId, aliceKid, '0', new Uint8Array([1]), [aliceKid], undefined, undefined, new Uint8Array([9]))
    const unsigned: Omit<ConversationExternalCommitSubmitV1, 'signature'> = { version: 1, groupId, senderKid: bobKid, epoch: '1', commit: new Uint8Array([2]), groupInfo: new Uint8Array([9]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationExternalCommitSubmitSigningBytes(unsigned), strangerKey) }
    expect(await submitConversationExternalCommit(ds, verifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(conversationExternalCommitSubmitSigningBytes(unsigned), bobKey) }
    const accepted = await submitConversationExternalCommit(ds, verifier(), valid)
    expect(accepted.ok).toBe(true)
    if (accepted.ok) expect(accepted.roster).toEqual([aliceKid, bobKid])
    ds.close()
  })

  test('pullConversationGroupInfo rejects a forged pull, answers a valid one -- from anyone, no identity check', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceKid, [])
    ds.submitCommit(groupId, aliceKid, '0', new Uint8Array([1]), [aliceKid], undefined, undefined, new Uint8Array([9]))
    const unsigned: Omit<ConversationGroupInfoPullV1, 'signature'> = { version: 1, groupId, requesterKid: bobKid, requestedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationGroupInfoPullSigningBytes(unsigned), strangerKey) }
    expect(await pullConversationGroupInfo(ds, verifier(), forged)).toEqual({ ok: false })

    // Bob, who has never been a member, still gets an authorized answer -- his own signature is all it takes.
    const valid = { ...unsigned, signature: ed25519.sign(conversationGroupInfoPullSigningBytes(unsigned), bobKey) }
    expect(await pullConversationGroupInfo(ds, verifier(), valid)).toEqual({ ok: true, answer: { groupInfo: new Uint8Array([9]), pendingRemovals: [] } })
    ds.close()
  })

  test('publishConversationKeyPackages and takeConversationKeyPackage both require the sender\'s own signature, take is targeted', async () => {
    const ds = open()
    const publishUnsigned: Omit<ConversationKeyPackagePublishV1, 'signature'> = { version: 1, kid: bobKid, packages: [new Uint8Array([1])], publishedAt: '2026-08-31T00:00:00.000Z' }
    const publishForged = { ...publishUnsigned, signature: ed25519.sign(conversationKeyPackagePublishSigningBytes(publishUnsigned), strangerKey) }
    expect(await publishConversationKeyPackages(ds, verifier(), publishForged)).toBeUndefined()

    const publishValid = { ...publishUnsigned, signature: ed25519.sign(conversationKeyPackagePublishSigningBytes(publishUnsigned), bobKey) }
    expect(await publishConversationKeyPackages(ds, verifier(), publishValid)).toBe(1)

    // Alice takes Bob's KeyPackage to add him to a group -- her signature, his targetKid.
    const takeUnsigned: Omit<ConversationKeyPackageTakeV1, 'signature'> = { version: 1, requesterKid: aliceKid, targetKid: bobKid, requestedAt: '2026-08-31T00:00:00.000Z' }
    const takeForged = { ...takeUnsigned, signature: ed25519.sign(conversationKeyPackageTakeSigningBytes(takeUnsigned), strangerKey) }
    expect(await takeConversationKeyPackage(ds, verifier(), takeForged)).toBeUndefined()

    const takeValid = { ...takeUnsigned, signature: ed25519.sign(conversationKeyPackageTakeSigningBytes(takeUnsigned), aliceKey) }
    expect(await takeConversationKeyPackage(ds, verifier(), takeValid)).toEqual({ keyPackage: new Uint8Array([1]) })
    ds.close()
  })

  test('submitConversationSelfRemove rejects a forged submission, accepts a valid one', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceKid, [])
    const unsigned: Omit<ConversationSelfRemoveSubmitV1, 'signature'> = { version: 1, groupId, senderKid: aliceKid, epoch: '0', proposal: new Uint8Array([1]), removedKid: aliceKid, submittedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationSelfRemoveSubmitSigningBytes(unsigned), strangerKey) }
    expect(await submitConversationSelfRemove(ds, verifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(conversationSelfRemoveSubmitSigningBytes(unsigned), aliceKey) }
    expect((await submitConversationSelfRemove(ds, verifier(), valid)).ok).toBe(true)
    expect(ds.groupInfoFor(groupId)?.pendingRemovals).toEqual([aliceKid])
    ds.close()
  })

  test('clearConversationPendingRemovals requires a signature, but a well-authorized non-committer is a silent DS no-op', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceKid, [])
    ds.submitSelfRemove(groupId, aliceKid, '0', new Uint8Array([1]), aliceKid)
    const unsigned: Omit<ConversationPendingRemovalsClearV1, 'signature'> = { version: 1, groupId, requesterKid: aliceKid, clearedKids: [aliceKid], clearedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationPendingRemovalsClearSigningBytes(unsigned), strangerKey) }
    expect(await clearConversationPendingRemovals(ds, verifier(), forged)).toBe(false)
    expect(ds.groupInfoFor(groupId)?.pendingRemovals).toEqual([aliceKid])

    const valid = { ...unsigned, signature: ed25519.sign(conversationPendingRemovalsClearSigningBytes(unsigned), aliceKey) }
    expect(await clearConversationPendingRemovals(ds, verifier(), valid)).toBe(true)
    // Alice never committed, so the DS quietly no-ops.
    expect(ds.groupInfoFor(groupId)?.pendingRemovals).toEqual([aliceKid])
    ds.close()
  })

  test('pullConversationDeliveries requires a signature and gates on ever-membership', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceKid, [])
    ds.submitCommit(groupId, aliceKid, '0', new Uint8Array([1]), [aliceKid])
    const unsigned: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId, requesterKid: aliceKid, afterSeq: 0, requestedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationDeliveriesPullSigningBytes(unsigned), strangerKey) }
    expect(await pullConversationDeliveries(ds, verifier(), forged)).toBeUndefined()

    const valid = { ...unsigned, signature: ed25519.sign(conversationDeliveriesPullSigningBytes(unsigned), aliceKey) }
    expect((await pullConversationDeliveries(ds, verifier(), valid))?.map(e => e.seq)).toEqual([1])
    ds.close()
  })

  test('dropConversationKeyPackages and pullConversationKeyPackageCount both require the sender\'s own signature', async () => {
    const ds = open()
    ds.publishKeyPackages(aliceKid, [new Uint8Array([1])])

    const countUnsigned: Omit<ConversationKeyPackageCountPullV1, 'signature'> = { version: 1, kid: aliceKid, requestedAt: '2026-08-31T00:00:00.000Z' }
    const countForged = { ...countUnsigned, signature: ed25519.sign(conversationKeyPackageCountPullSigningBytes(countUnsigned), strangerKey) }
    expect(await pullConversationKeyPackageCount(ds, verifier(), countForged)).toBeUndefined()
    const countValid = { ...countUnsigned, signature: ed25519.sign(conversationKeyPackageCountPullSigningBytes(countUnsigned), aliceKey) }
    expect(await pullConversationKeyPackageCount(ds, verifier(), countValid)).toBe(1)

    const dropUnsigned: Omit<ConversationKeyPackageDropV1, 'signature'> = { version: 1, kid: aliceKid, droppedAt: '2026-08-31T00:00:00.000Z' }
    const dropForged = { ...dropUnsigned, signature: ed25519.sign(conversationKeyPackageDropSigningBytes(dropUnsigned), strangerKey) }
    expect(await dropConversationKeyPackages(ds, verifier(), dropForged)).toBe(false)
    expect(ds.keyPackageCount(aliceKid)).toBe(1)

    const dropValid = { ...dropUnsigned, signature: ed25519.sign(conversationKeyPackageDropSigningBytes(dropUnsigned), aliceKey) }
    expect(await dropConversationKeyPackages(ds, verifier(), dropValid)).toBe(true)
    expect(ds.keyPackageCount(aliceKid)).toBe(0)
    ds.close()
  })

  test('pullConversationGroupsFor requires a signature and answers with every group the requester has been in', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceKid, [])
    const unsigned: Omit<ConversationGroupsForPullV1, 'signature'> = { version: 1, requesterKid: aliceKid, requestedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationGroupsForPullSigningBytes(unsigned), strangerKey) }
    expect(await pullConversationGroupsFor(ds, verifier(), forged)).toBeUndefined()

    const valid = { ...unsigned, signature: ed25519.sign(conversationGroupsForPullSigningBytes(unsigned), aliceKey) }
    expect(await pullConversationGroupsFor(ds, verifier(), valid)).toEqual([{ groupId, epoch: 0n }])
    ds.close()
  })

  test('submitConversationMessage (no Self Group equivalent) requires a signature and fans out via the log', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceKid, [bobKid])
    const unsigned: Omit<ConversationMessageSubmitV1, 'signature'> = { version: 1, groupId, senderKid: aliceKid, epoch: '0', privateMessage: new Uint8Array([1, 2, 3]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationMessageSubmitSigningBytes(unsigned), strangerKey) }
    expect(await submitConversationMessage(ds, verifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(conversationMessageSubmitSigningBytes(unsigned), aliceKey) }
    const accepted = await submitConversationMessage(ds, verifier(), valid)
    expect(accepted.ok).toBe(true)
    if (accepted.ok) expect(accepted.entries[0]).toMatchObject({ kind: 'application', payload: new Uint8Array([1, 2, 3]) })
    ds.close()
  })
})
