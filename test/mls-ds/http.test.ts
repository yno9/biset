import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '../../src/protocol/canonical.ts'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationWatchTokenIssuer } from '../../src/mls-ds/watch-token.ts'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'
import {
  conversationCommitSubmitSigningBytes, conversationDeliveriesPullSigningBytes, conversationDeliveriesWatchSigningBytes, conversationGroupCreateSigningBytes,
  conversationKeyPackagePublishSigningBytes, conversationKeyPackageTakeSigningBytes, conversationMessageSubmitSigningBytes,
  conversationSelfRemoveSubmitSigningBytes,
} from '../../src/protocol/conversation-mls-ds-signing.ts'
import type {
  ConversationCommitSubmitV1, ConversationDeliveriesPullV1, ConversationDeliveriesWatchV1, ConversationGroupCreateV1, ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1, ConversationMessageSubmitV1, ConversationSelfRemoveSubmitV1,
} from '../../src/protocol/conversation-mls-ds.ts'

const path = `/tmp/biset-conversation-ds-http-${process.pid}-${Date.now()}.sqlite`
const aliceKey = ed25519.utils.randomSecretKey()
const aliceId = bytesToHex(ed25519.getPublicKey(aliceKey))

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function handler() {
  const ds = SqliteConversationDeliveryService.open(path)
  const handle = createConversationDeliveryHttpHandler(ds, new Ed25519ConversationDsSignatureVerifier(), new ConversationWatchTokenIssuer())
  return { ds, handle }
}

function body(json: unknown): string {
  return JSON.stringify(json)
}

describe('Conversation Group DS HTTP endpoint (identity-blind: no deviceCredential field, no DIDComm binding)', () => {
  test('group/create then commit/submit round-trips through the wire format', async () => {
    const { ds, handle } = handler()
    const creation: Omit<ConversationGroupCreateV1, 'signature'> = { version: 1, groupId: 'group-1', creatorId: aliceId, createdAt: '2026-08-31T00:00:00.000Z' }
    const createResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/group/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...creation, signature: bytesToBase64url(ed25519.sign(conversationGroupCreateSigningBytes(creation), aliceKey)) }),
    }))
    expect(createResponse.status).toBe(201)
    expect(await createResponse.json()).toEqual({ roster: [aliceId] })

    const commit: Omit<ConversationCommitSubmitV1, 'signature'> = {
      version: 1, groupId: 'group-1', senderId: aliceId, epoch: '0',
      commit: new Uint8Array([1, 2, 3]), submittedAt: '2026-08-31T00:01:00.000Z',
    }
    const commitResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/commit/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...commit, commit: bytesToBase64url(commit.commit), signature: bytesToBase64url(ed25519.sign(conversationCommitSubmitSigningBytes(commit), aliceKey)) }),
    }))
    expect(commitResponse.status).toBe(201)
    expect(await commitResponse.json()).toEqual({ roster: [aliceId] })
    ds.close()
  })

  test('a forged commit submission is rejected with 403 and does not advance the epoch', async () => {
    const { ds, handle } = handler()
    const strangerKey = ed25519.utils.randomSecretKey()
    ds.createGroup('group-1', aliceId)
    const commit: Omit<ConversationCommitSubmitV1, 'signature'> = {
      version: 1, groupId: 'group-1', senderId: aliceId, epoch: '0',
      commit: new Uint8Array([1]), submittedAt: '2026-08-31T00:00:00.000Z',
    }
    const response = await handle(new Request('https://mls-ds.example/v1/conversation-mls/commit/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...commit, commit: bytesToBase64url(commit.commit), signature: bytesToBase64url(ed25519.sign(conversationCommitSubmitSigningBytes(commit), strangerKey)) }),
    }))
    expect(response.status).toBe(403)
    expect(ds.roster('group-1')).toEqual([aliceId])
    ds.close()
  })

  test('key package publish then take round-trips binary packages through base64url', async () => {
    const { ds, handle } = handler()
    const publish: Omit<ConversationKeyPackagePublishV1, 'signature'> = { version: 1, id: aliceId, packages: [new Uint8Array([9, 9])], publishedAt: '2026-08-31T00:00:00.000Z' }
    const publishResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/keypackage/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...publish, packages: publish.packages.map(bytesToBase64url), signature: bytesToBase64url(ed25519.sign(conversationKeyPackagePublishSigningBytes(publish), aliceKey)) }),
    }))
    expect(publishResponse.status).toBe(200)
    expect(await publishResponse.json()).toEqual({ count: 1 })

    const take: Omit<ConversationKeyPackageTakeV1, 'signature'> = { version: 1, requesterId: aliceId, targetId: aliceId, requestedAt: '2026-08-31T00:01:00.000Z' }
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
    // Removed endpoints (GroupInfo/external-commit/groups-for) are simply unknown paths now.
    expect((await handle(new Request('https://mls-ds.example/v1/conversation-mls/group-info/pull', { method: 'POST', body: '{}' }))).status).toBe(404)
    expect((await handle(new Request('https://mls-ds.example/v1/conversation-mls/commit/external', { method: 'POST', body: '{}' }))).status).toBe(404)
    expect((await handle(new Request('https://mls-ds.example/v1/conversation-mls/groups-for', { method: 'POST', body: '{}' }))).status).toBe(404)
    ds.close()
  })

  test('self-remove/submit then deliveries/pull round-trip through the wire format', async () => {
    const { ds, handle } = handler()
    ds.createGroup('group-1', aliceId)
    ds.submitCommit('group-1', aliceId, '0', new Uint8Array([1]))

    const selfRemove: Omit<ConversationSelfRemoveSubmitV1, 'signature'> = { version: 1, groupId: 'group-1', senderId: aliceId, epoch: '1', proposal: new Uint8Array([7]), removedId: aliceId, submittedAt: '2026-08-31T00:00:00.000Z' }
    const selfRemoveResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/self-remove/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...selfRemove, proposal: bytesToBase64url(selfRemove.proposal), signature: bytesToBase64url(ed25519.sign(conversationSelfRemoveSubmitSigningBytes(selfRemove), aliceKey)) }),
    }))
    expect(selfRemoveResponse.status).toBe(201)

    const pull: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId: 'group-1', requesterId: aliceId, afterSeq: 0, requestedAt: '2026-08-31T00:01:00.000Z' }
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
    ds.createGroup('group-1', aliceId)

    const submit: Omit<ConversationMessageSubmitV1, 'signature'> = { version: 1, groupId: 'group-1', senderId: aliceId, epoch: '0', privateMessage: new Uint8Array([4, 5, 6]), submittedAt: '2026-08-31T00:00:00.000Z' }
    const response = await handle(new Request('https://mls-ds.example/v1/conversation-mls/message/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...submit, privateMessage: bytesToBase64url(submit.privateMessage), signature: bytesToBase64url(ed25519.sign(conversationMessageSubmitSigningBytes(submit), aliceKey)) }),
    }))
    expect(response.status).toBe(201)

    const stale: Omit<ConversationMessageSubmitV1, 'signature'> = { version: 1, groupId: 'group-1', senderId: aliceId, epoch: '99', privateMessage: new Uint8Array([1]), submittedAt: '2026-08-31T00:00:01.000Z' }
    const staleResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/message/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...stale, privateMessage: bytesToBase64url(stale.privateMessage), signature: bytesToBase64url(ed25519.sign(conversationMessageSubmitSigningBytes(stale), aliceKey)) }),
    }))
    expect(staleResponse.status).toBe(409)
    expect(await staleResponse.json()).toEqual({ reason: 'epoch-conflict', epoch: '0' })
    ds.close()
  })

  test('deliveries/watch mints a token (rejecting a forged mint), and GET deliveries/stream serves backlog then live entries, unsubscribing on cancel', async () => {
    const { ds, handle } = handler()
    ds.createGroup('group-1', aliceId)
    ds.submitCommit('group-1', aliceId, '0', new Uint8Array([1])) // backlog: one commit at seq 1

    const watch: Omit<ConversationDeliveriesWatchV1, 'signature'> = { version: 1, groupId: 'group-1', requesterId: aliceId, requestedAt: '2026-08-31T00:00:00.000Z' }
    const forged = await handle(new Request('https://mls-ds.example/v1/conversation-mls/deliveries/watch', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: body({ ...watch, signature: bytesToBase64url(ed25519.sign(conversationDeliveriesWatchSigningBytes(watch), ed25519.utils.randomSecretKey())) }),
    }))
    expect(forged.status).toBe(403)

    const watchResponse = await handle(new Request('https://mls-ds.example/v1/conversation-mls/deliveries/watch', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: body({ ...watch, signature: bytesToBase64url(ed25519.sign(conversationDeliveriesWatchSigningBytes(watch), aliceKey)) }),
    }))
    expect(watchResponse.status).toBe(200)
    const { token } = await watchResponse.json() as { token: string; expiresAt: string }
    expect(typeof token).toBe('string')

    const streamResponse = await handle(new Request(`https://mls-ds.example/v1/conversation-mls/deliveries/stream?token=${token}&afterSeq=0`))
    expect(streamResponse.status).toBe(200)
    expect(streamResponse.headers.get('content-type')).toBe('text/event-stream')
    expect(ds.subscriberCount('group-1')).toBe(1)

    const reader = streamResponse.body!.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    async function readFrame(): Promise<string> {
      for (;;) {
        while (!buffer.includes('\n\n')) {
          const { value, done } = await reader.read()
          if (done) throw new Error('stream ended unexpectedly')
          buffer += decoder.decode(value, { stream: true })
        }
        const idx = buffer.indexOf('\n\n')
        const frame = buffer.slice(0, idx)
        buffer = buffer.slice(idx + 2)
        // A `:`-prefixed line is an SSE comment (the connect-flush and the
        // 15s heartbeat, both http.ts) -- EventSource never surfaces these
        // as a message, so a reader that mimics real client behavior skips
        // them too rather than asserting on them.
        if (!frame.startsWith(':')) return frame
      }
    }

    const backlogFrame = await readFrame()
    expect(backlogFrame).toContain('id: 1')
    expect(backlogFrame).toMatch(/"kind":"commit"/)

    ds.submitMessage('group-1', aliceId, '1', new Uint8Array([9]))
    const liveFrame = await readFrame()
    expect(liveFrame).toContain('id: 2')
    expect(liveFrame).toMatch(/"kind":"application"/)

    await reader.cancel()
    expect(ds.subscriberCount('group-1')).toBe(0)
    ds.close()
  })

  test('GET deliveries/stream rejects a missing or invalid/expired token', async () => {
    const { ds, handle } = handler()
    const missing = await handle(new Request('https://mls-ds.example/v1/conversation-mls/deliveries/stream?afterSeq=0'))
    expect(missing.status).toBe(400)
    const invalid = await handle(new Request('https://mls-ds.example/v1/conversation-mls/deliveries/stream?token=nope&afterSeq=0'))
    expect(invalid.status).toBe(403)
    ds.close()
  })
})
