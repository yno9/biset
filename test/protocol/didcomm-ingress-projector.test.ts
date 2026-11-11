import { describe, expect, test } from 'vitest'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { packAnoncrypt, packAuthcrypt } from '../../src/protocol/didcomm/crypto.ts'
import { signDidCommMessage } from '../../src/protocol/didcomm/jws.ts'
import { buildPlaintext } from '../../src/protocol/didcomm/message.ts'
import { PING, PING_RESPONSE } from '../../src/protocol/didcomm/trust-ping.ts'
import { PROBLEM_REPORT } from '../../src/protocol/didcomm/problems.ts'
import type { LocalJmapEmail } from '../../src/client/store/projection/gateway.ts'
import { BASIC_MESSAGE, didCommThreadOf } from '../../src/client/didcomm/basicmessage.ts'
import { didOfKid } from '../../src/protocol/ids.ts'
import { DidCommIngressProjector, DidCommReplayError } from '../../src/client/didcomm/ingress-projector.ts'
import { generatePeerIdentity } from '../../src/protocol/didcomm/peer.ts'
import { didcommGroupAddress } from '../../src/client/didcomm/group-chat.ts'
import { decryptVaultObject } from '../../src/client/store/vault/objects.ts'
import type { VaultEventAuthor } from '../../src/client/store/vault/events.ts'
import { ingestIngress } from '../../src/client/store/vault/ingress-ingest.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'

const identityId = 'did:vh:abc123'
const recipientKid = `${identityId}#k_devicehash`
const senderKid = 'did:vh:def456#k_senderhash'

const signer: VaultEventAuthor = {
  deviceId: recipientKid,
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === recipientKid && equalBytes(signature, await this.sign(bytes)) },
}

const senderX = x25519.utils.randomSecretKey()
const senderXPub = x25519.getPublicKey(senderX)
const recipientX = x25519.utils.randomSecretKey()
const recipientXPub = x25519.getPublicKey(recipientX)

const segmentKey = createSegmentKey()
async function segmentFor() {
  return { segmentId: 'segment-1', segmentKey }
}

function envelopeFor(payload: Uint8Array, ingressId = 'ingress-1'): IngressEnvelopeV1 {
  return {
    version: 1, ingressId, protocol: 'didcomm', recipientIdentityId: identityId, recipientDeviceSnapshot: [recipientKid],
    createdAt: '2026-08-25T00:00:00.000Z', expiresAt: '2026-08-26T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([1]),
    protectedPayload: payload, protectedPayloadHash: sha256Bytes(payload),
  }
}

/** Auto-marking stub: the first check for a given controlId succeeds (and
 * remembers it), a second check for the SAME id reports "already
 * processed" -- exactly the property a real store-backed implementation
 * has to provide, without this test needing to know the id's derivation. */
function autoMarkingAlreadyProcessed(): (id: string) => Promise<boolean> {
  const seen = new Set<string>()
  return async (id) => {
    if (seen.has(id)) return true
    seen.add(id)
    return false
  }
}

function buildProjector(alreadyProcessed = autoMarkingAlreadyProcessed(), emails: LocalJmapEmail[] = []) {
  return new DidCommIngressProjector({
    identityId, actorDeviceId: recipientKid,
    resolveOwnKey(kid) { return kid === recipientKid ? { kid: recipientKid, x25519PrivateKey: recipientX } : null },
    async resolveSenderKey(kid) { if (kid !== senderKid) throw new Error('unexpected sender kid ' + kid); return senderXPub },
    alreadyProcessed,
    async nextActorSeq() { return 1 },
    async initialParents() { return [] },
    activeSegment: segmentFor,
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails, contactCards: [] } },
    signer,
    now: () => new Date('2026-08-25T00:01:00.000Z'),
  })
}

function pingJwe(responseRequested = true) {
  const plaintext = buildPlaintext(PING, { response_requested: responseRequested }, didOfKid(senderKid))
  const jwe = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
    { kid: senderKid, privateKey: senderX },
    [{ kid: recipientKid, publicKey: recipientXPub }],
  )
  return { plaintext, jwe }
}

describe('DIDComm ingress projector', () => {
  test('a trust-ping decrypts, verifies the sender, and lands as a didcomm.control vault event + sibling delivery outbox', async () => {
    const { jwe } = pingJwe(true)
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    const projector = buildProjector()

    let committed = false
    const result = await ingestIngress(envelope, signer, projector, {
      async commitIngress(input) {
        committed = true
        // The ping, and the card made for its sender on first contact.
        expect(input.events.map(event => event.kind)).toEqual(['didcomm.control', 'contact.set'])
        expect(input.objects.map(o => o.objectId)).toEqual(input.events.flatMap(event => event.objectRefs))
        expect(input.projection.contactCards).toMatchObject([{ onlineServices: { didcomm: { service: 'DIDComm', uri: didOfKid(senderKid) } } }])

        const plaintextObject = await decryptVaultObject(segmentKey, input.objects[0]!)
        const decoded = JSON.parse(new TextDecoder().decode(plaintextObject)) as { payload: Record<string, unknown> }
        expect(decoded.payload.type).toBe(PING)
        expect(decoded.payload.senderKid).toBe(senderKid)
        expect(decoded.payload.responseOwed).toBe(true)
        return 'committed'
      },
    }, () => new Date('2026-08-25T00:01:01.000Z'))
    expect(committed).toBe(true)
    expect(result.ack.vaultEventId).toBeTruthy()
  })

  test('response_requested:false is recorded as no response owed', async () => {
    expect(PING_RESPONSE).toBe('https://didcomm.org/trust-ping/2.0/ping-response')
    const { jwe } = pingJwe(false)
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    const projector = buildProjector()
    await ingestIngress(envelope, signer, projector, {
      async commitIngress(input) {
        const plaintextObject = await decryptVaultObject(segmentKey, input.objects[0]!)
        const decoded = JSON.parse(new TextDecoder().decode(plaintextObject)) as { payload: Record<string, unknown> }
        expect(decoded.payload.responseOwed).toBe(false)
        return 'committed'
      },
    })
  })

  test('a captured JWE resubmitted under a NEW ingressId is rejected as a replay (same senderKid + message id, different envelope)', async () => {
    const { jwe } = pingJwe(true)
    const payloadBytes = new TextEncoder().encode(JSON.stringify(jwe))
    const projector = buildProjector()

    const first = envelopeFor(payloadBytes, 'ingress-1')
    await ingestIngress(first, signer, projector, { async commitIngress() { return 'committed' } })

    const replay = envelopeFor(payloadBytes, 'ingress-2-a-different-envelope-id')
    await expect(ingestIngress(replay, signer, projector, {
      async commitIngress() { throw new Error('must not be reached for a detected replay') },
    })).rejects.toBeInstanceOf(DidCommReplayError)
  })

  test('a message id is compared case-insensitively: the same id in other case is the same message (DIDComm v2.1)', async () => {
    const plaintext = buildPlaintext(PING, { response_requested: false }, didOfKid(senderKid), undefined, { id: 'abc-DEF-123' })
    const again = { ...plaintext, id: 'ABC-def-123' }
    const pack = (value: object) => envelopeFor(new TextEncoder().encode(JSON.stringify(packAuthcrypt(new TextEncoder().encode(JSON.stringify(value)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }]))), crypto.randomUUID())
    const projector = buildProjector()
    await projector.verifyAndProject(pack(plaintext))
    await expect(projector.verifyAndProject(pack(again))).rejects.toBeInstanceOf(DidCommReplayError)
  })

  test('a group thread id in other case is the same thread', async () => {
    const carol = 'did:vh:ghi789'
    const pack = (thid: string) => envelopeFor(new TextEncoder().encode(JSON.stringify(packAuthcrypt(new TextEncoder().encode(JSON.stringify(buildPlaintext(BASIC_MESSAGE, { content: 'hi' }, didOfKid(senderKid), [identityId, carol], { thid }))), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }]))), crypto.randomUUID())
    const upper = await buildProjector().verifyAndProject(pack('Group-ABC'))
    const lower = await buildProjector().verifyAndProject(pack('group-abc'))
    expect(upper.projection.emails[0]!.threadId).toBe(lower.projection.emails[0]!.threadId)
  })

  test('a different ping (new message id) from the same sender is NOT treated as a replay', async () => {
    const projector = buildProjector()
    const { jwe: first } = pingJwe(true)
    await ingestIngress(envelopeFor(new TextEncoder().encode(JSON.stringify(first)), 'ingress-1'), signer, projector, { async commitIngress() { return 'committed' } })

    const { jwe: second } = pingJwe(true) // buildPlaintext mints a fresh crypto.randomUUID() id each call
    const result = await ingestIngress(envelopeFor(new TextEncoder().encode(JSON.stringify(second)), 'ingress-2'), signer, projector, { async commitIngress() { return 'committed' } })
    expect(result.ack.vaultEventId).toBeTruthy()
  })

  test('a JWE claiming to be from senderKid but signed by an impostor key fails to authenticate (sender-auth)', async () => {
    const impostorX = x25519.utils.randomSecretKey()
    const plaintext = buildPlaintext(PING, { response_requested: true }, didOfKid(senderKid))
    // packAuthcrypt with the IMPOSTOR's private key but senderKid's own kid
    // string in the header -- resolveSenderKey still returns the REAL
    // senderXPub (the only key it knows for that kid), so ECDH-1PU's Zs
    // won't match and the AEAD tag check fails.
    const jwe = packAuthcrypt(
      new TextEncoder().encode(JSON.stringify(plaintext)),
      { kid: senderKid, privateKey: impostorX },
      [{ kid: recipientKid, publicKey: recipientXPub }],
    )
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    const projector = buildProjector()
    await expect(projector.verifyAndProject(envelope)).rejects.toThrow()
  })

  test('a device whose kid is not the JWE\'s addressed recipient fails cleanly, not with data corruption', async () => {
    const { jwe } = pingJwe(true)
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    const wrongDeviceKid = `${identityId}#k_someotherdevice`
    const wrongDeviceX = x25519.utils.randomSecretKey()
    const projector = new DidCommIngressProjector({
      identityId, actorDeviceId: wrongDeviceKid,
      resolveOwnKey(kid) { return kid === wrongDeviceKid ? { kid: wrongDeviceKid, x25519PrivateKey: wrongDeviceX } : null },
      async resolveSenderKey() { return senderXPub },
      async alreadyProcessed() { return false },
      async nextActorSeq() { return 1 },
      async initialParents() { return [] },
      activeSegment: segmentFor,
      async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
      signer: { ...signer, deviceId: wrongDeviceKid },
    })
    await expect(projector.verifyAndProject(envelope)).rejects.toThrow(/recipient kids .* is available/)
  })

  test('a message encrypted for every device of this identity opens on whichever device this is, not only the first listed', async () => {
    const otherDeviceKid = `${identityId}#k_firstdevice`
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'to all of your devices' }, didOfKid(senderKid), identityId)
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [
      { kid: otherDeviceKid, publicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()) },
      { kid: recipientKid, publicKey: recipientXPub },
    ])
    const result = await buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.projection.emails).toHaveLength(1)
  })

  test('the SAME envelope succeeds for the actually-addressed device after a wrong device declined it (multidevice ingress)', async () => {
    const { jwe } = pingJwe(true)
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    const wrongDeviceKid = `${identityId}#k_someotherdevice`
    const wrongProjector = new DidCommIngressProjector({
      identityId, actorDeviceId: wrongDeviceKid,
      resolveOwnKey(kid) { return kid === wrongDeviceKid ? { kid: wrongDeviceKid, x25519PrivateKey: x25519.utils.randomSecretKey() } : null },
      async resolveSenderKey() { return senderXPub },
      async alreadyProcessed() { return false },
      async nextActorSeq() { return 1 },
      async initialParents() { return [] },
      activeSegment: segmentFor,
      async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
      signer: { ...signer, deviceId: wrongDeviceKid },
    })
    await expect(wrongProjector.verifyAndProject(envelope)).rejects.toThrow()

    const rightProjector = buildProjector()
    const result = await ingestIngress(envelope, signer, rightProjector, { async commitIngress() { return 'committed' } })
    expect(result.ack.vaultEventId).toBeTruthy()
  })

  test('an unsupported DIDComm message type is rejected, not silently dropped', async () => {
    const plaintext = buildPlaintext('https://didcomm.org/discover-features/2.0/queries', { content: 'hi' }, didOfKid(senderKid))
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    const projector = buildProjector()
    await expect(projector.verifyAndProject(envelope)).rejects.toThrow(/unsupported DIDComm message type/)
  })

  test('the retired relationship INIT is an unsupported type', async () => {
    const plaintext = buildPlaintext('https://biset.md/relationship/1.0/init', { relationshipKid: 'did:peer:2.x#key-1', publicKey: 'AA' }, didOfKid(senderKid))
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    await expect(buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))).rejects.toThrow(/unsupported DIDComm message type/)
  })

  test('an anoncrypt message signed by its sender (DIDComm v2.1 signed messages) is recorded as the signer\'s', async () => {
    const signingKey = ed25519.utils.randomSecretKey()
    const signerKid = 'did:vh:def456#signing'
    const message = buildPlaintext(BASIC_MESSAGE, { content: 'signed, not authcrypted' }, didOfKid(senderKid), identityId)
    const signed = signDidCommMessage(message, signerKid, signingKey)
    const jwe = packAnoncrypt(new TextEncoder().encode(JSON.stringify(signed)), [{ kid: recipientKid, publicKey: recipientXPub }])
    const projector = new DidCommIngressProjector({
      identityId, actorDeviceId: recipientKid,
      resolveOwnKey(kid) { return kid === recipientKid ? { kid, x25519PrivateKey: recipientX } : null },
      async resolveSenderKey() { throw new Error('anoncrypt has no sender key') },
      async resolveSigningKey(kid) { if (kid !== signerKid) throw new Error('unexpected signer'); return { type: 'Ed25519' as const, publicKey: ed25519.getPublicKey(signingKey) } },
      async alreadyProcessed() { return false },
      async nextActorSeq() { return 1 },
      async initialParents() { return [] },
      activeSegment: segmentFor,
      async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
      signer,
    })
    const result = await projector.verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.projection.emails).toMatchObject([{ from: [{ email: didOfKid(senderKid) }] }])
    // An anoncrypt message nobody signed is still only for External Feed Post.
    const unsigned = packAnoncrypt(new TextEncoder().encode(JSON.stringify(message)), [{ kid: recipientKid, publicKey: recipientXPub }])
    await expect(projector.verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(unsigned)), 'ingress-2'))).rejects.toThrow('unauthenticated')
  })

  test('a basicmessage from a did:peer nobody names is recorded under that DID, and no contact card is made for it (PLAN-refactor.md §14.3)', async () => {
    const agent = generatePeerIdentity({ uri: 'https://agent-mediator.test.example' })
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'hello from an agent' }, agent.did, identityId)
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: agent.xKid, privateKey: agent.xPriv }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const projector = new DidCommIngressProjector({
      identityId, actorDeviceId: recipientKid,
      resolveOwnKey(kid) { return kid === recipientKid ? { kid, x25519PrivateKey: recipientX } : null },
      async resolveSenderKey(kid) { if (kid !== agent.xKid) throw new Error('unexpected sender'); return agent.xPub },
      async alreadyProcessed() { return false },
      async nextActorSeq() { return 1 },
      async initialParents() { return [] },
      activeSegment: segmentFor,
      async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
      signer,
    })
    const result = await projector.verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.projection.emails).toMatchObject([{ from: [{ email: agent.did }], to: [{ email: identityId }], threadId: didCommThreadOf(identityId, agent.did, plaintext.id) }])
    expect(result.projection.contactCards).toEqual([])
  })

  test('a basicmessage addressed to several parties lands in the group thread its thid names, with every recipient in `to`', async () => {
    const carol = 'did:vh:ghi789'
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'hello, both of you', subject: 'Planning' }, didOfKid(senderKid), [identityId, carol], { thid: 'group-1' })
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const result = await buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.projection.emails).toMatchObject([{
      from: [{ email: didOfKid(senderKid) }], to: [{ email: identityId }, { email: carol }],
      threadId: didcommGroupAddress('group-1'), subject: 'Planning',
    }])
  })

  test('a group message that starts its own thread (no thid) is threaded by its id', async () => {
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'new group' }, didOfKid(senderKid), [identityId, 'did:vh:ghi789'], { id: 'first-message' })
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const result = await buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.projection.emails[0]!.threadId).toBe(didcommGroupAddress('first-message'))
  })

  test('a group message that does not name this identity among its recipients is rejected', async () => {
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'not for you' }, didOfKid(senderKid), ['did:vh:x', 'did:vh:y'], { thid: 'group-2' })
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    await expect(buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))).rejects.toThrow(/does not name this identity/)
  })

  test('a basicmessage decrypts, verifies the sender, and lands as an ordinary message.add email in the recipient\'s own inbox', async () => {
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'hey, are we really chatting over DIDComm now?', sentAt: '2026-08-25T00:00:00.000Z' }, didOfKid(senderKid))
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    const projector = buildProjector()

    const result = await ingestIngress(envelope, signer, projector, {
      async commitIngress(input) {
        expect(input.objects).toHaveLength(3) // metadata + raw body, same shape as mail; and the sender's new card
        expect(input.events.map(event => event.kind)).toEqual(['message.add', 'contact.set'])
        expect(input.projection).toMatchObject({
          emails: [{ from: [{ email: didOfKid(senderKid) }], to: [{ email: identityId }], threadId: didCommThreadOf(identityId, didOfKid(senderKid), plaintext.id) }],
        })
        return 'committed'
      },
    })
    expect(result.ack.vaultEventId).toBeTruthy()
  })

  test('a bridged mail keeps its id, the From: name, the Reply-To DID and the auth results; unknown auth values are dropped', async () => {
    const replyTo = 'did:web:did.md:example.com:list'
    const plaintext = buildPlaintext(BASIC_MESSAGE, {
      content: 'hello from mail', subject: 'Hi', fromName: 'Bob Example', replyTo,
      auth: { spf: 'pass', dkim: 'bogus', dmarc: 'fail', domain: 'example.com', extra: 'x' },
    }, didOfKid(senderKid), undefined, { id: 'CAF00@mail.example.com' })
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const result = await buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.projection.emails).toMatchObject([{
      from: [{ email: didOfKid(senderKid), name: 'Bob Example' }], subject: 'Hi',
      messageId: 'CAF00@mail.example.com', replyTo: [{ email: replyTo }],
      auth: { spf: 'pass', dmarc: 'fail', domain: 'example.com' },
    }])
    expect(result.projection.emails[0]!.auth).toEqual({ spf: 'pass', dmarc: 'fail', domain: 'example.com' })
  })

  test('a problem-report (a bridge\'s delivery failure) is recorded, not a thread row', async () => {
    const plaintext = buildPlaintext(PROBLEM_REPORT, { code: 'e.m.xfer.rejected', comment: 'refused for {1}: {2}', args: ['a@b.example', '550'] }, didOfKid(senderKid), [identityId], { pthid: 'Sent-1' })
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const result = await buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.events.map(event => event.kind)).toEqual(['didcomm.control'])
    expect(result.projection.emails).toEqual([])
  })

  test('basicmessages between the same pair: each without a thid is a thread of its own; one carrying that thid is in it', async () => {
    const projector = buildProjector()
    const threadOf = async (content: string, ingressId: string, thid?: string): Promise<{ id: string; threadId: string }> => {
      const message = buildPlaintext(BASIC_MESSAGE, { content }, didOfKid(senderKid), undefined, thid ? { thid } : {})
      const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(message)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
      let threadId = ''
      await ingestIngress(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)), ingressId), signer, projector, {
        async commitIngress(input) { threadId = (input.projection as { emails: Array<{ threadId: string }> }).emails[0]!.threadId; return 'committed' },
      })
      return { id: message.id, threadId }
    }
    const first = await threadOf('first message', 'ingress-1')
    const second = await threadOf('second message', 'ingress-2')
    const reply = await threadOf('a reply in the first', 'ingress-3', first.id)
    expect(first.threadId).not.toBe(second.threadId)
    expect(first.threadId).toBe(didCommThreadOf(identityId, didOfKid(senderKid), first.id))
    expect(reply.threadId).toBe(first.threadId)
  })

  test('mail from a bridge: each is a thread of its own, its thid (the message it answers) is its inReplyTo', async () => {
    const bridgeKid = 'did:web:did.md:gmail.com:alice#key-x25519-1'
    const projector = new DidCommIngressProjector({
      identityId, actorDeviceId: recipientKid,
      resolveOwnKey(kid) { return kid === recipientKid ? { kid: recipientKid, x25519PrivateKey: recipientX } : null },
      async resolveSenderKey(kid) { if (kid !== bridgeKid) throw new Error('unexpected sender kid ' + kid); return senderXPub },
      alreadyProcessed: autoMarkingAlreadyProcessed(),
      async nextActorSeq() { return 1 },
      async initialParents() { return [] },
      activeSegment: segmentFor,
      async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
      signer,
      now: () => new Date('2026-08-25T00:01:00.000Z'),
    })
    const emailOf = async (content: string, ingressId: string, thid?: string) => {
      const message = buildPlaintext(BASIC_MESSAGE, { content }, didOfKid(bridgeKid), undefined, thid ? { thid } : {})
      const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(message)), { kid: bridgeKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
      let email: { threadId: string; inReplyTo?: string } | undefined
      await ingestIngress(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)), ingressId), signer, projector, {
        async commitIngress(input) { email = (input.projection as { emails: Array<{ threadId: string; inReplyTo?: string }> }).emails[0]; return 'committed' },
      })
      return { id: message.id, email: email! }
    }
    const first = await emailOf('a mail', 'ingress-1')
    const answer = await emailOf('an answer to our message', 'ingress-2', 'our-message-id')
    expect(first.email.threadId).toBe(didCommThreadOf(identityId, didOfKid(bridgeKid), first.id))
    expect(first.email.inReplyTo).toBeUndefined()
    expect(answer.email.threadId).toBe(didCommThreadOf(identityId, didOfKid(bridgeKid), answer.id))
    expect(answer.email.inReplyTo).toBe('our-message-id')
  })

  test('an expired message is rejected', async () => {
    const plaintext = buildPlaintext(PING, { response_requested: true }, didOfKid(senderKid))
    plaintext.expires_time = Math.floor(Date.parse('2020-01-01T00:00:00.000Z') / 1000)
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    const projector = buildProjector()
    await expect(projector.verifyAndProject(envelope)).rejects.toThrow(/expired/)
  })
})
