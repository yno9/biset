import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'
import {
  conversationCommitSubmitSigningBytes, conversationDeliveriesPullSigningBytes, conversationGroupCreateSigningBytes,
  conversationKeyPackagePublishSigningBytes, conversationKeyPackageTakeSigningBytes, conversationMessageSubmitSigningBytes,
  conversationSelfRemoveSubmitSigningBytes,
} from '../../src/protocol/conversation-mls-ds-signing.ts'
import type {
  ConversationCommitSubmitV1, ConversationDeliveriesPullV1, ConversationGroupCreateV1, ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1, ConversationMessageSubmitV1, ConversationSelfRemoveSubmitV1,
} from '../../src/protocol/conversation-mls-ds.ts'

const path = `/tmp/biset-conversation-ds-http-${process.pid}-${Date.now()}.sqlite`
const aliceKey = ed25519.utils.randomSecretKey()
const alicePublicKey = ed25519.getPublicKey(aliceKey)
const aliceKid = 'did:web:alice.example#key-1'

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function handler() {
  const ds = SqliteConversationDeliveryService.open(path)
  const verifier = new Ed25519ConversationDsSignatureVerifier({ async resolveEd25519PublicKey(kid) { return kid === aliceKid ? alicePublicKey : undefined } })
  const handle = createConversationDeliveryHttpHandler(ds, verifier)
  return { ds, handle }
}

function body(json: unknown): string {
  return JSON.stringify(json && typeof json === 'object' ? { ...json, deviceCredential: bytesToBase64url(new Uint8Array([1])) } : json)
}

describe('Conversation Group DS HTTP endpoint (first transport, DIDComm binding to follow)', () => {
  test('group/create then commit/submit round-trips through the wire format', async () => {
    const { ds, handle } = handler()
    const creation: Omit<ConversationGroupCreateV1, 'signature'> = { version: 1, groupId: 'group-1', creatorKid: aliceKid, roster: [], createdAt: '2026-08-31T00:00:00.000Z' }
    const createResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/group/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...creation, signature: bytesToBase64url(ed25519.sign(conversationGroupCreateSigningBytes(creation), aliceKey)) }),
    }))
    expect(createResponse.status).toBe(201)
    expect(await createResponse.json()).toEqual({ roster: [aliceKid] })

    const commit: Omit<ConversationCommitSubmitV1, 'signature'> = {
      version: 1, groupId: 'group-1', senderKid: aliceKid, epoch: '0',
      commit: new Uint8Array([1, 2, 3]), roster: [aliceKid], submittedAt: '2026-08-31T00:01:00.000Z',
    }
    const commitResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/commit/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...commit, commit: bytesToBase64url(commit.commit), signature: bytesToBase64url(ed25519.sign(conversationCommitSubmitSigningBytes(commit), aliceKey)) }),
    }))
    expect(commitResponse.status).toBe(201)
    expect(await commitResponse.json()).toEqual({ roster: [aliceKid] })
    ds.close()
  })

  test('a forged commit submission is rejected with 403 and does not advance the epoch', async () => {
    const { ds, handle } = handler()
    const strangerKey = ed25519.utils.randomSecretKey()
    ds.createGroup('group-1', aliceKid, [])
    const commit: Omit<ConversationCommitSubmitV1, 'signature'> = {
      version: 1, groupId: 'group-1', senderKid: aliceKid, epoch: '0',
      commit: new Uint8Array([1]), roster: [aliceKid], submittedAt: '2026-08-31T00:00:00.000Z',
    }
    const response = await handle(new Request('https://mls-ds.example/v1/conversation-mls/commit/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...commit, commit: bytesToBase64url(commit.commit), signature: bytesToBase64url(ed25519.sign(conversationCommitSubmitSigningBytes(commit), strangerKey)) }),
    }))
    expect(response.status).toBe(403)
    expect(ds.roster('group-1')).toEqual([aliceKid])
    ds.close()
  })

  test('key package publish then take round-trips binary packages through base64url', async () => {
    const { ds, handle } = handler()
    const publish: Omit<ConversationKeyPackagePublishV1, 'signature'> = { version: 1, kid: aliceKid, packages: [new Uint8Array([9, 9])], publishedAt: '2026-08-31T00:00:00.000Z' }
    const publishResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/keypackage/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...publish, packages: publish.packages.map(bytesToBase64url), signature: bytesToBase64url(ed25519.sign(conversationKeyPackagePublishSigningBytes(publish), aliceKey)) }),
    }))
    expect(publishResponse.status).toBe(200)
    expect(await publishResponse.json()).toEqual({ count: 1 })

    const take: Omit<ConversationKeyPackageTakeV1, 'signature'> = { version: 1, requesterKid: aliceKid, targetKid: aliceKid, requestedAt: '2026-08-31T00:01:00.000Z' }
    const takeResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/keypackage/take', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...take, signature: bytesToBase64url(ed25519.sign(conversationKeyPackageTakeSigningBytes(take), aliceKey)) }),
    }))
    expect(takeResponse.status).toBe(200)
    expect(await takeResponse.json()).toEqual({ keyPackage: bytesToBase64url(new Uint8Array([9, 9])) })
    ds.close()
  })

  test('an unknown path is 404, a non-POST method is 405', async () => {
    const { ds, handle } = handler()
    expect((await handle(new Request('https://mls-ds.example/v1/conversation-mls/nope', { method: 'POST', body: '{}' }))).status).toBe(404)
    expect((await handle(new Request('https://mls-ds.example/v1/conversation-mls/group/create', { method: 'GET' }))).status).toBe(405)
    ds.close()
  })

  test('self-remove/submit then deliveries/pull round-trip through the wire format', async () => {
    const { ds, handle } = handler()
    ds.createGroup('group-1', aliceKid, [])
    ds.submitCommit('group-1', aliceKid, '0', new Uint8Array([1]), [aliceKid])

    const selfRemove: Omit<ConversationSelfRemoveSubmitV1, 'signature'> = { version: 1, groupId: 'group-1', senderKid: aliceKid, epoch: '1', proposal: new Uint8Array([7]), removedKid: aliceKid, submittedAt: '2026-08-31T00:00:00.000Z' }
    const selfRemoveResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/self-remove/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...selfRemove, proposal: bytesToBase64url(selfRemove.proposal), signature: bytesToBase64url(ed25519.sign(conversationSelfRemoveSubmitSigningBytes(selfRemove), aliceKey)) }),
    }))
    expect(selfRemoveResponse.status).toBe(201)

    const pull: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId: 'group-1', requesterKid: aliceKid, afterSeq: 0, requestedAt: '2026-08-31T00:01:00.000Z' }
    const pullResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/deliveries/pull', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...pull, signature: bytesToBase64url(ed25519.sign(conversationDeliveriesPullSigningBytes(pull), aliceKey)) }),
    }))
    expect(pullResponse.status).toBe(200)
    const parsed = await pullResponse.json() as { entries: Array<{ seq: number; kind: string }> }
    expect(parsed.entries.map(e => ({ seq: e.seq, kind: e.kind }))).toEqual([{ seq: 1, kind: 'commit' }, { seq: 2, kind: 'proposal' }])
    ds.close()
  })

  test('message/submit (no Self Group equivalent) round-trips application data and rejects a stale epoch', async () => {
    const { ds, handle } = handler()
    ds.createGroup('group-1', aliceKid, [])

    const submit: Omit<ConversationMessageSubmitV1, 'signature'> = { version: 1, groupId: 'group-1', senderKid: aliceKid, epoch: '0', privateMessage: new Uint8Array([4, 5, 6]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const response = await handle(new Request('https://mls-ds.example/v1/conversation-mls/message/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...submit, privateMessage: bytesToBase64url(submit.privateMessage), signature: bytesToBase64url(ed25519.sign(conversationMessageSubmitSigningBytes(submit), aliceKey)) }),
    }))
    expect(response.status).toBe(201)

    const stale: Omit<ConversationMessageSubmitV1, 'signature'> = { version: 1, groupId: 'group-1', senderKid: aliceKid, epoch: '99', privateMessage: new Uint8Array([1]), submittedAt: '2026-08-31T00:00:01.000Z' }
    const staleResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/message/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...stale, privateMessage: bytesToBase64url(stale.privateMessage), signature: bytesToBase64url(ed25519.sign(conversationMessageSubmitSigningBytes(stale), aliceKey)) }),
    }))
    expect(staleResponse.status).toBe(409)
    expect(await staleResponse.json()).toEqual({ reason: 'epoch-conflict', epoch: '0' })
    ds.close()
  })
})
