import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '../../src/protocol/canonical.ts'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import {
  clearConversationPendingRemovals, createConversationGroup, dropConversationKeyPackages, Ed25519ConversationDsSignatureVerifier,
  publishConversationKeyPackages, pullConversationDeliveries, pullConversationKeyPackageCount,
  submitConversationCommit, submitConversationMessage, submitConversationSelfRemove, takeConversationKeyPackage,
} from '../../src/mls-ds/authorizer.ts'
import {
  conversationCommitSubmitSigningBytes, conversationDeliveriesPullSigningBytes,
  conversationGroupCreateSigningBytes, conversationKeyPackageCountPullSigningBytes,
  conversationKeyPackageDropSigningBytes, conversationKeyPackagePublishSigningBytes,
  conversationKeyPackageTakeSigningBytes, conversationMessageSubmitSigningBytes, conversationPendingRemovalsClearSigningBytes,
  conversationSelfRemoveSubmitSigningBytes,
} from '../../src/protocol/conversation-mls-ds-signing.ts'
import type {
  ConversationCommitSubmitV1, ConversationDeliveriesPullV1, ConversationGroupCreateV1,
  ConversationKeyPackageCountPullV1, ConversationKeyPackageDropV1,
  ConversationKeyPackagePublishV1, ConversationKeyPackageTakeV1, ConversationMessageSubmitV1, ConversationPendingRemovalsClearV1,
  ConversationSelfRemoveSubmitV1,
} from '../../src/protocol/conversation-mls-ds.ts'

const path = `/tmp/biset-conversation-ds-auth-${process.pid}-${Date.now()}.sqlite`
const groupId = 'group-1'
const aliceKey = ed25519.utils.randomSecretKey()
const aliceId = bytesToHex(ed25519.getPublicKey(aliceKey))
const bobKey = ed25519.utils.randomSecretKey()
const bobId = bytesToHex(ed25519.getPublicKey(bobKey))
const strangerKey = ed25519.utils.randomSecretKey()

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function open(): SqliteConversationDeliveryService { return SqliteConversationDeliveryService.open(path) }

describe('Conversation Group DS authorizer (identity-blind: the group-local id IS the verification key, no resolution)', () => {
  test('createConversationGroup accepts a validly self-signed genesis, rejects a forged one', async () => {
    const ds = open()
    const unsigned: Omit<ConversationGroupCreateV1, 'signature'> = { version: 1, groupId, creatorId: aliceId, createdAt: '2026-08-31T00:00:00.000Z' }
    const valid = { ...unsigned, signature: ed25519.sign(conversationGroupCreateSigningBytes(unsigned), aliceKey) }
    expect(await createConversationGroup(ds, new Ed25519ConversationDsSignatureVerifier(), valid)).toEqual({ ok: true, roster: [aliceId] })

    const forged = { ...unsigned, groupId: 'group-2', signature: ed25519.sign(conversationGroupCreateSigningBytes(unsigned), strangerKey) }
    expect(await createConversationGroup(ds, new Ed25519ConversationDsSignatureVerifier(), forged)).toEqual({ ok: false })
    ds.close()
  })

  test('rejects an id that is not a valid 32-byte hex public key, rather than throwing', async () => {
    const ds = open()
    const unsigned: Omit<ConversationGroupCreateV1, 'signature'> = { version: 1, groupId, creatorId: 'not-hex-at-all', createdAt: '2026-08-31T00:00:00.000Z' }
    const value = { ...unsigned, signature: ed25519.sign(conversationGroupCreateSigningBytes(unsigned), aliceKey) }
    expect(await createConversationGroup(ds, new Ed25519ConversationDsSignatureVerifier(), value)).toEqual({ ok: false })
    ds.close()
  })

  test('submitConversationCommit rejects a forged submission without touching DS state', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceId)
    const unsigned: Omit<ConversationCommitSubmitV1, 'signature'> = { version: 1, groupId, senderId: aliceId, epoch: '0', commit: new Uint8Array([1]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationCommitSubmitSigningBytes(unsigned), strangerKey) }
    expect(await submitConversationCommit(ds, new Ed25519ConversationDsSignatureVerifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(conversationCommitSubmitSigningBytes(unsigned), aliceKey) }
    expect((await submitConversationCommit(ds, new Ed25519ConversationDsSignatureVerifier(), valid)).ok).toBe(true)
    ds.close()
  })

  test('submitConversationCommit addedIds adds a new member by group-local id, with no DID or resolution involved', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceId)
    const unsigned: Omit<ConversationCommitSubmitV1, 'signature'> = { version: 1, groupId, senderId: aliceId, epoch: '0', commit: new Uint8Array([1]), addedIds: [bobId], welcome: new Uint8Array([2]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const valid = { ...unsigned, signature: ed25519.sign(conversationCommitSubmitSigningBytes(unsigned), aliceKey) }
    const accepted = await submitConversationCommit(ds, new Ed25519ConversationDsSignatureVerifier(), valid)
    expect(accepted.ok).toBe(true)
    if (accepted.ok) expect(accepted.roster).toEqual([aliceId, bobId])
    ds.close()
  })

  test('publishConversationKeyPackages and takeConversationKeyPackage both require the sender\'s own signature, take is targeted', async () => {
    const ds = open()
    const publishUnsigned: Omit<ConversationKeyPackagePublishV1, 'signature'> = { version: 1, id: bobId, packages: [new Uint8Array([1])], publishedAt: '2026-08-31T00:00:00.000Z' }
    const publishForged = { ...publishUnsigned, signature: ed25519.sign(conversationKeyPackagePublishSigningBytes(publishUnsigned), strangerKey) }
    expect(await publishConversationKeyPackages(ds, new Ed25519ConversationDsSignatureVerifier(), publishForged)).toBeUndefined()

    const publishValid = { ...publishUnsigned, signature: ed25519.sign(conversationKeyPackagePublishSigningBytes(publishUnsigned), bobKey) }
    expect(await publishConversationKeyPackages(ds, new Ed25519ConversationDsSignatureVerifier(), publishValid)).toBe(1)

    // Alice takes Bob's KeyPackage to add him to a group -- her signature, his targetId. Neither side needs to be a member yet.
    const takeUnsigned: Omit<ConversationKeyPackageTakeV1, 'signature'> = { version: 1, requesterId: aliceId, targetId: bobId, requestedAt: '2026-08-31T00:00:00.000Z' }
    const takeForged = { ...takeUnsigned, signature: ed25519.sign(conversationKeyPackageTakeSigningBytes(takeUnsigned), strangerKey) }
    expect(await takeConversationKeyPackage(ds, new Ed25519ConversationDsSignatureVerifier(), takeForged)).toBeUndefined()

    const takeValid = { ...takeUnsigned, signature: ed25519.sign(conversationKeyPackageTakeSigningBytes(takeUnsigned), aliceKey) }
    expect(await takeConversationKeyPackage(ds, new Ed25519ConversationDsSignatureVerifier(), takeValid)).toEqual({ keyPackage: new Uint8Array([1]) })
    ds.close()
  })

  test('submitConversationSelfRemove rejects a forged submission, accepts a valid one', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceId)
    const unsigned: Omit<ConversationSelfRemoveSubmitV1, 'signature'> = { version: 1, groupId, senderId: aliceId, epoch: '0', proposal: new Uint8Array([1]), removedId: aliceId, submittedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationSelfRemoveSubmitSigningBytes(unsigned), strangerKey) }
    expect(await submitConversationSelfRemove(ds, new Ed25519ConversationDsSignatureVerifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(conversationSelfRemoveSubmitSigningBytes(unsigned), aliceKey) }
    expect((await submitConversationSelfRemove(ds, new Ed25519ConversationDsSignatureVerifier(), valid)).ok).toBe(true)
    ds.close()
  })

  test('clearConversationPendingRemovals requires a signature, but a well-authorized non-committer is a silent DS no-op', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceId)
    ds.submitSelfRemove(groupId, aliceId, '0', new Uint8Array([1]), aliceId)
    const unsigned: Omit<ConversationPendingRemovalsClearV1, 'signature'> = { version: 1, groupId, requesterId: aliceId, clearedIds: [aliceId], clearedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationPendingRemovalsClearSigningBytes(unsigned), strangerKey) }
    expect(await clearConversationPendingRemovals(ds, new Ed25519ConversationDsSignatureVerifier(), forged)).toBe(false)

    const valid = { ...unsigned, signature: ed25519.sign(conversationPendingRemovalsClearSigningBytes(unsigned), aliceKey) }
    // Alice never committed, so the DS quietly no-ops -- still returns true (authorized), just no effect.
    expect(await clearConversationPendingRemovals(ds, new Ed25519ConversationDsSignatureVerifier(), valid)).toBe(true)
    ds.close()
  })

  test('pullConversationDeliveries requires a signature and gates on ever-membership', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceId)
    ds.submitCommit(groupId, aliceId, '0', new Uint8Array([1]))
    const unsigned: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId, requesterId: aliceId, afterSeq: 0, requestedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationDeliveriesPullSigningBytes(unsigned), strangerKey) }
    expect(await pullConversationDeliveries(ds, new Ed25519ConversationDsSignatureVerifier(), forged)).toBeUndefined()

    const valid = { ...unsigned, signature: ed25519.sign(conversationDeliveriesPullSigningBytes(unsigned), aliceKey) }
    expect((await pullConversationDeliveries(ds, new Ed25519ConversationDsSignatureVerifier(), valid))?.map(e => e.seq)).toEqual([1])
    ds.close()
  })

  test('dropConversationKeyPackages and pullConversationKeyPackageCount both require the sender\'s own signature', async () => {
    const ds = open()
    ds.publishKeyPackages(aliceId, [new Uint8Array([1])])

    const countUnsigned: Omit<ConversationKeyPackageCountPullV1, 'signature'> = { version: 1, id: aliceId, requestedAt: '2026-08-31T00:00:00.000Z' }
    const countForged = { ...countUnsigned, signature: ed25519.sign(conversationKeyPackageCountPullSigningBytes(countUnsigned), strangerKey) }
    expect(await pullConversationKeyPackageCount(ds, new Ed25519ConversationDsSignatureVerifier(), countForged)).toBeUndefined()
    const countValid = { ...countUnsigned, signature: ed25519.sign(conversationKeyPackageCountPullSigningBytes(countUnsigned), aliceKey) }
    expect(await pullConversationKeyPackageCount(ds, new Ed25519ConversationDsSignatureVerifier(), countValid)).toBe(1)

    const dropUnsigned: Omit<ConversationKeyPackageDropV1, 'signature'> = { version: 1, id: aliceId, droppedAt: '2026-08-31T00:00:00.000Z' }
    const dropForged = { ...dropUnsigned, signature: ed25519.sign(conversationKeyPackageDropSigningBytes(dropUnsigned), strangerKey) }
    expect(await dropConversationKeyPackages(ds, new Ed25519ConversationDsSignatureVerifier(), dropForged)).toBe(false)
    expect(ds.keyPackageCount(aliceId)).toBe(1)

    const dropValid = { ...dropUnsigned, signature: ed25519.sign(conversationKeyPackageDropSigningBytes(dropUnsigned), aliceKey) }
    expect(await dropConversationKeyPackages(ds, new Ed25519ConversationDsSignatureVerifier(), dropValid)).toBe(true)
    expect(ds.keyPackageCount(aliceId)).toBe(0)
    ds.close()
  })

  test('submitConversationMessage (no Self Group equivalent) requires a signature and logs it', async () => {
    const ds = open()
    ds.createGroup(groupId, aliceId)
    ds.submitCommit(groupId, aliceId, '0', new Uint8Array([1]), [bobId])
    const unsigned: Omit<ConversationMessageSubmitV1, 'signature'> = { version: 1, groupId, senderId: aliceId, epoch: '1', privateMessage: new Uint8Array([1, 2, 3]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(conversationMessageSubmitSigningBytes(unsigned), strangerKey) }
    expect(await submitConversationMessage(ds, new Ed25519ConversationDsSignatureVerifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(conversationMessageSubmitSigningBytes(unsigned), aliceKey) }
    const accepted = await submitConversationMessage(ds, new Ed25519ConversationDsSignatureVerifier(), valid)
    expect(accepted.ok).toBe(true)
    if (accepted.ok) expect(accepted.entries[0]).toMatchObject({ kind: 'application', payload: new Uint8Array([1, 2, 3]) })
    ds.close()
  })
})
