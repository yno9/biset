import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { handleConversationDsMessage } from '../../src/mls-ds/didcomm.ts'
import * as T from '../../src/mls-ds/didcomm-types.ts'
import { buildPlaintext } from '../../src/didcomm/message.ts'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'
import type { SendDidCommMessageOptions } from '../../src/didcomm/send-message.ts'
import {
  conversationCommitSubmitSigningBytes, conversationDeliveriesPullSigningBytes, conversationGroupCreateSigningBytes,
  conversationGroupInfoPullSigningBytes, conversationKeyPackageTakeSigningBytes, conversationMessageSubmitSigningBytes,
} from '../../src/protocol/conversation-mls-ds-signing.ts'

const path = `/tmp/biset-conversation-ds-didcomm-${process.pid}-${Date.now()}.sqlite`
const dsDid = 'did:web:mls-ds.example'
const aliceKey = ed25519.utils.randomSecretKey()
const alicePublicKey = ed25519.getPublicKey(aliceKey)
const aliceKid = 'did:web:alice.example#key-1'
// message-submit's fan-out (fanout.ts) resolves each OTHER member's DID to
// deliver message-notify -- a 404 stand-in keeps that network-free and
// deterministic here, same as fanout.test.ts. resolveWithRouting's resolve()
// half ignores `opts.fetch` and always uses the real global fetch (same note
// as webvh-resolve-sender-key.test.ts), so it's pinned globally too.
const notFound: typeof fetch = (async () => new Response('not found', { status: 404 })) as typeof fetch
const sendOpts: SendDidCommMessageOptions = { fromKid: `${dsDid}#key-1`, x25519PrivateKey: new Uint8Array(32), fetch: notFound }

let realFetch: typeof fetch
beforeEach(() => { realFetch = globalThis.fetch; globalThis.fetch = notFound })
afterEach(() => { globalThis.fetch = realFetch })

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function open() {
  const ds = SqliteConversationDeliveryService.open(path)
  const verifier = new Ed25519ConversationDsSignatureVerifier({ async resolveEd25519PublicKey(kid) { return kid === aliceKid ? alicePublicKey : undefined } })
  return { ds, verifier }
}

describe('Conversation Group DS DIDComm binding (Phase 2b, same engine as HTTP)', () => {
  test('group-create: success gets no response, DS state updates', async () => {
    const { ds, verifier } = open()
    const unsigned = { version: 1 as const, groupId: 'group-1', creatorKid: aliceKid, roster: [], createdAt: '2026-08-31T00:00:00.000Z' }
    const body = { ...unsigned, deviceCredential: bytesToBase64url(new Uint8Array([1])), signature: bytesToBase64url(ed25519.sign(conversationGroupCreateSigningBytes(unsigned), aliceKey)) }
    const request = buildPlaintext(T.GROUP_CREATE, body, aliceKid, dsDid)

    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect(response).toBeNull()
    expect(ds.roster('group-1')).toEqual([aliceKid])
    ds.close()
  })

  test('group-create: a forged signature gets a problem-report, not silence', async () => {
    const { ds, verifier } = open()
    const strangerKey = ed25519.utils.randomSecretKey()
    const unsigned = { version: 1 as const, groupId: 'group-1', creatorKid: aliceKid, roster: [], createdAt: '2026-08-31T00:00:00.000Z' }
    const body = { ...unsigned, deviceCredential: bytesToBase64url(new Uint8Array([1])), signature: bytesToBase64url(ed25519.sign(conversationGroupCreateSigningBytes(unsigned), strangerKey)) }
    const request = buildPlaintext(T.GROUP_CREATE, body, aliceKid, dsDid)

    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect(response?.type).toBe('https://didcomm.org/report-problem/2.0/problem-report')
    expect((response?.body as { code: string }).code).toBe('e.p.unauthorized')
    expect(response?.pthid).toBe(request.id)
    expect(response?.ack).toEqual([request.id])
    ds.close()
  })

  test('commit-submit: an epoch conflict maps to e.p.epoch-conflict, not a generic rejection', async () => {
    const { ds, verifier } = open()
    ds.createGroup('group-1', aliceKid, [])
    ds.submitCommit('group-1', aliceKid, '0', new Uint8Array([1]), [aliceKid])
    const unsigned = { version: 1 as const, groupId: 'group-1', senderKid: aliceKid, epoch: '0', commit: new Uint8Array([2]), roster: [aliceKid], submittedAt: '2026-08-31T00:01:00.000Z' }
    const body = { ...unsigned, commit: bytesToBase64url(unsigned.commit), deviceCredential: bytesToBase64url(new Uint8Array([1])), signature: bytesToBase64url(ed25519.sign(conversationCommitSubmitSigningBytes(unsigned), aliceKey)) }
    const request = buildPlaintext(T.COMMIT_SUBMIT, body, aliceKid, dsDid)

    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect((response?.body as { code: string }).code).toBe('e.p.epoch-conflict')
    ds.close()
  })

  test('group-info-pull: response threads via thid, carries groupInfo/pendingRemovals', async () => {
    const { ds, verifier } = open()
    ds.createGroup('group-1', aliceKid, [])
    ds.submitCommit('group-1', aliceKid, '0', new Uint8Array([1]), [aliceKid], undefined, undefined, new Uint8Array([9]))
    const unsigned = { version: 1 as const, groupId: 'group-1', requesterKid: aliceKid, requestedAt: '2026-08-31T00:02:00.000Z' }
    const body = { ...unsigned, deviceCredential: bytesToBase64url(new Uint8Array([1])), signature: bytesToBase64url(ed25519.sign(conversationGroupInfoPullSigningBytes(unsigned), aliceKey)) }
    const request = buildPlaintext(T.GROUP_INFO_PULL, body, aliceKid, dsDid)

    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect(response?.type).toBe(T.GROUP_INFO)
    expect(response?.thid).toBe(request.id)
    expect(response?.from).toBe(dsDid)
    expect(response?.to).toEqual([aliceKid])
    expect(response?.body).toEqual({ groupInfo: bytesToBase64url(new Uint8Array([9])), pendingRemovals: [] })
    ds.close()
  })

  test('keypackage-take: no package available maps to e.p.no-key-package', async () => {
    const { ds, verifier } = open()
    const unsigned = { version: 1 as const, requesterKid: aliceKid, targetKid: aliceKid, requestedAt: '2026-08-31T00:03:00.000Z' }
    const body = { ...unsigned, deviceCredential: bytesToBase64url(new Uint8Array([1])), signature: bytesToBase64url(ed25519.sign(conversationKeyPackageTakeSigningBytes(unsigned), aliceKey)) }
    const request = buildPlaintext(T.KEYPACKAGE_TAKE, body, aliceKid, dsDid)

    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect((response?.body as { code: string }).code).toBe('e.p.no-key-package')
    ds.close()
  })

  test('deliveries-pull: response carries entries as base64url', async () => {
    const { ds, verifier } = open()
    ds.createGroup('group-1', aliceKid, [])
    ds.submitCommit('group-1', aliceKid, '0', new Uint8Array([7]), [aliceKid])
    const unsigned = { version: 1 as const, groupId: 'group-1', requesterKid: aliceKid, afterSeq: 0, requestedAt: '2026-08-31T00:04:00.000Z' }
    const body = { ...unsigned, deviceCredential: bytesToBase64url(new Uint8Array([1])), signature: bytesToBase64url(ed25519.sign(conversationDeliveriesPullSigningBytes(unsigned), aliceKey)) }
    const request = buildPlaintext(T.DELIVERIES_PULL, body, aliceKid, dsDid)

    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect(response?.type).toBe(T.DELIVERIES)
    const entries = (response?.body as { entries: Array<{ kind: string; payload: string }> }).entries
    expect(entries).toHaveLength(1)
    expect(entries[0]!.kind).toBe('commit')
    expect(entries[0]!.payload).toBe(bytesToBase64url(new Uint8Array([7])))
    ds.close()
  })

  test('message-submit: success gets no response, DS log advances', async () => {
    const { ds, verifier } = open()
    ds.createGroup('group-1', aliceKid, [])
    const unsigned = { version: 1 as const, groupId: 'group-1', senderKid: aliceKid, epoch: '0', privateMessage: new Uint8Array([4, 5, 6]), submittedAt: '2026-08-31T00:05:00.000Z' }
    const body = { ...unsigned, privateMessage: bytesToBase64url(unsigned.privateMessage), deviceCredential: bytesToBase64url(new Uint8Array([1])), signature: bytesToBase64url(ed25519.sign(conversationMessageSubmitSigningBytes(unsigned), aliceKey)) }
    const request = buildPlaintext(T.MESSAGE_SUBMIT, body, aliceKid, dsDid)

    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect(response).toBeNull()
    expect(ds.deliveriesSince('group-1', aliceKid, 0).map(e => e.kind)).toEqual(['application'])
    ds.close()
  })

  test('message-submit: with other members present, fan-out runs (best-effort) without breaking the submitter\'s own null response', async () => {
    const { ds, verifier } = open()
    // bobKid is never given a resolvable DID document (notFound fetch) --
    // this exercises fanOutApplicationMessage's best-effort path from
    // inside the DIDComm handler, not just fanout.test.ts's direct unit test.
    ds.createGroup('group-1', aliceKid, ['did:web:bob.example#key-1'])
    const unsigned = { version: 1 as const, groupId: 'group-1', senderKid: aliceKid, epoch: '0', privateMessage: new Uint8Array([7, 8, 9]), submittedAt: '2026-08-31T00:06:00.000Z' }
    const body = { ...unsigned, privateMessage: bytesToBase64url(unsigned.privateMessage), deviceCredential: bytesToBase64url(new Uint8Array([1])), signature: bytesToBase64url(ed25519.sign(conversationMessageSubmitSigningBytes(unsigned), aliceKey)) }
    const request = buildPlaintext(T.MESSAGE_SUBMIT, body, aliceKid, dsDid)

    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect(response).toBeNull()
    ds.close()
  })

  test('an unsupported message type gets a problem-report rather than being silently dropped', async () => {
    const { ds, verifier } = open()
    const request = buildPlaintext('https://biset.md/mls-ds/1.0/nonsense', {}, aliceKid, dsDid)
    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect(response?.type).toBe('https://didcomm.org/report-problem/2.0/problem-report')
    ds.close()
  })

  test('a request with no `from` gets a problem-report instead of throwing', async () => {
    const { ds, verifier } = open()
    const request = buildPlaintext(T.GROUP_CREATE, {}, undefined, dsDid)
    const response = await handleConversationDsMessage(ds, verifier, request, dsDid, sendOpts)
    expect(response?.type).toBe('https://didcomm.org/report-problem/2.0/problem-report')
    ds.close()
  })
})
