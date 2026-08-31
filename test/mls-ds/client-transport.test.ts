// End-to-end: ConversationMlsDeliveryTransport (client) against
// createConversationDeliveryHttpHandler (mls-ds/http.ts), through the
// shared protocol/conversation-mls-ds-wire.ts encode/decode -- confirms the
// client and server sides of the wire actually agree, mirroring
// mls-delivery-client-transport.test.ts's Self Group version.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '../../src/protocol/canonical.ts'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationWatchTokenIssuer } from '../../src/mls-ds/watch-token.ts'
import { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'
import {
  conversationCommitSubmitSigningBytes, conversationDeliveriesPullSigningBytes, conversationDeliveriesWatchSigningBytes, conversationGroupCreateSigningBytes,
  conversationKeyPackageCountPullSigningBytes,
  conversationKeyPackageDropSigningBytes, conversationKeyPackagePublishSigningBytes, conversationKeyPackageTakeSigningBytes,
  conversationMessageSubmitSigningBytes, conversationPendingRemovalsClearSigningBytes, conversationSelfRemoveSubmitSigningBytes,
} from '../../src/protocol/conversation-mls-ds-signing.ts'
import type {
  ConversationCommitSubmitV1, ConversationDeliveriesPullV1, ConversationDeliveriesWatchV1, ConversationGroupCreateV1,
  ConversationKeyPackageCountPullV1, ConversationKeyPackageDropV1, ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1, ConversationMessageSubmitV1, ConversationPendingRemovalsClearV1, ConversationSelfRemoveSubmitV1,
} from '../../src/protocol/conversation-mls-ds.ts'

const path = `/tmp/biset-conversation-ds-client-${process.pid}-${Date.now()}.sqlite`
const groupId = 'group-1'
const aliceKey = ed25519.utils.randomSecretKey()
const aliceId = bytesToHex(ed25519.getPublicKey(aliceKey))

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function setup() {
  const ds = SqliteConversationDeliveryService.open(path)
  const handle = createConversationDeliveryHttpHandler(ds, new Ed25519ConversationDsSignatureVerifier(), new ConversationWatchTokenIssuer())
  const transport = new ConversationMlsDeliveryTransport({ baseUrl: 'https://mls-ds.example', fetch: (input, init) => handle(new Request(input, init)) })
  return { ds, transport }
}

describe('ConversationMlsDeliveryTransport <-> Conversation Group DS HTTP handler (identity-blind)', () => {
  test('createGroup then submitCommit round-trip, and a stale-epoch retry surfaces as ok:false, not a throw', async () => {
    const { ds, transport } = setup()
    const creation: Omit<ConversationGroupCreateV1, 'signature'> = { version: 1, groupId, creatorId: aliceId, createdAt: '2026-08-31T00:00:00.000Z' }
    const roster = await transport.createGroup({ ...creation, signature: ed25519.sign(conversationGroupCreateSigningBytes(creation), aliceKey) })
    expect(roster).toEqual([aliceId])

    const commit: Omit<ConversationCommitSubmitV1, 'signature'> = { version: 1, groupId, senderId: aliceId, epoch: '0', commit: new Uint8Array([1]), submittedAt: '2026-08-31T00:00:01.000Z' }
    const accepted = await transport.submitCommit({ ...commit, signature: ed25519.sign(conversationCommitSubmitSigningBytes(commit), aliceKey) })
    expect(accepted).toEqual({ ok: true, roster: [aliceId] })

    const stale = await transport.submitCommit({ ...commit, signature: ed25519.sign(conversationCommitSubmitSigningBytes(commit), aliceKey) })
    expect(stale).toEqual({ ok: false, reason: 'epoch-conflict', epoch: '1' })
    ds.close()
  })

  test('publishKeyPackages / takeKeyPackage / dropKeyPackages / keyPackageCount round-trip binary payloads', async () => {
    const { ds, transport } = setup()
    const publish: Omit<ConversationKeyPackagePublishV1, 'signature'> = { version: 1, id: aliceId, packages: [new Uint8Array([1, 2]), new Uint8Array([3])], publishedAt: '2026-08-31T00:00:00.000Z' }
    expect(await transport.publishKeyPackages({ ...publish, signature: ed25519.sign(conversationKeyPackagePublishSigningBytes(publish), aliceKey) })).toBe(2)

    const countPull: Omit<ConversationKeyPackageCountPullV1, 'signature'> = { version: 1, id: aliceId, requestedAt: '2026-08-31T00:00:01.000Z' }
    expect(await transport.keyPackageCount({ ...countPull, signature: ed25519.sign(conversationKeyPackageCountPullSigningBytes(countPull), aliceKey) })).toBe(2)

    const take: Omit<ConversationKeyPackageTakeV1, 'signature'> = { version: 1, requesterId: aliceId, targetId: aliceId, requestedAt: '2026-08-31T00:00:02.000Z' }
    const taken = await transport.takeKeyPackage({ ...take, signature: ed25519.sign(conversationKeyPackageTakeSigningBytes(take), aliceKey) })
    expect(taken).toEqual({ keyPackage: new Uint8Array([1, 2]) })

    const drop: Omit<ConversationKeyPackageDropV1, 'signature'> = { version: 1, id: aliceId, droppedAt: '2026-08-31T00:00:03.000Z' }
    await transport.dropKeyPackages({ ...drop, signature: ed25519.sign(conversationKeyPackageDropSigningBytes(drop), aliceKey) })
    expect(ds.keyPackageCount(aliceId)).toBe(0)
    ds.close()
  })

  test('submitSelfRemove / clearPendingRemovals / pullDeliveries round-trip', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, aliceId)
    ds.submitCommit(groupId, aliceId, '0', new Uint8Array([1]))

    const selfRemove: Omit<ConversationSelfRemoveSubmitV1, 'signature'> = { version: 1, groupId, senderId: aliceId, epoch: '1', proposal: new Uint8Array([5]), removedId: aliceId, submittedAt: '2026-08-31T00:00:00.000Z' }
    const removed = await transport.submitSelfRemove({ ...selfRemove, signature: ed25519.sign(conversationSelfRemoveSubmitSigningBytes(selfRemove), aliceKey) })
    expect(removed.ok).toBe(true)

    const clear: Omit<ConversationPendingRemovalsClearV1, 'signature'> = { version: 1, groupId, requesterId: aliceId, clearedIds: [aliceId], clearedAt: '2026-08-31T00:00:01.000Z' }
    await transport.clearPendingRemovals({ ...clear, signature: ed25519.sign(conversationPendingRemovalsClearSigningBytes(clear), aliceKey) })

    const pull: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId, requesterId: aliceId, afterSeq: 0, requestedAt: '2026-08-31T00:00:02.000Z' }
    const entries = await transport.pullDeliveries({ ...pull, signature: ed25519.sign(conversationDeliveriesPullSigningBytes(pull), aliceKey) })
    expect(entries.map(e => ({ seq: e.seq, kind: e.kind }))).toEqual([{ seq: 1, kind: 'commit' }, { seq: 2, kind: 'proposal' }])
    ds.close()
  })

  test('submitMessage (no Self Group equivalent) round-trips application data', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, aliceId)
    const submit: Omit<ConversationMessageSubmitV1, 'signature'> = { version: 1, groupId, senderId: aliceId, epoch: '0', privateMessage: new Uint8Array([4, 5, 6]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const accepted = await transport.submitMessage({ ...submit, signature: ed25519.sign(conversationMessageSubmitSigningBytes(submit), aliceKey) })
    expect(accepted.ok).toBe(true)
    expect(ds.deliveriesSince(groupId, aliceId, 0)?.map(e => e.kind)).toEqual(['application'])
    ds.close()
  })

  test('watchDeliveries mints a token and streamUrl builds a URL carrying it, matching the DS\'s own GET route', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, aliceId)
    const watch: Omit<ConversationDeliveriesWatchV1, 'signature'> = { version: 1, groupId, requesterId: aliceId, requestedAt: '2026-08-31T00:00:00.000Z' }
    const { token, expiresAt } = await transport.watchDeliveries({ ...watch, signature: ed25519.sign(conversationDeliveriesWatchSigningBytes(watch), aliceKey) })
    expect(typeof token).toBe('string')
    expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now())
    const url = transport.streamUrl(token, 0)
    expect(url).toBe(`https://mls-ds.example/v1/conversation-mls/deliveries/stream?token=${token}&afterSeq=0`)
    ds.close()
  })
})
