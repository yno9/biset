import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { packAuthcrypt } from '../../src/protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../../src/protocol/didcomm/message.ts'
import { PING, PING_RESPONSE } from '../../src/protocol/didcomm/trust-ping.ts'
import { BASIC_MESSAGE, didCommThreadId } from '../../src/client/didcomm/basicmessage.ts'
import { didOfKid } from '../../src/protocol/ids.ts'
import { DidCommIngressProjector, DidCommReplayError } from '../../src/client/didcomm/ingress-projector.ts'
import { generatePeerIdentity } from '../../src/protocol/didcomm/peer.ts'
import { didcommGroupAddress } from '../../src/client/didcomm/group-chat.ts'
import { decryptVaultObject } from '../../src/client/store/vault/objects.ts'
import type { VaultEventAuthor } from '../../src/client/store/vault/events.ts'
import { ingestIngress } from '../../src/client/store/vault/ingress-ingest.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'

const identityId = 'did:webvh:abc123:alice.test.example'
const recipientKid = `${identityId}#k_devicehash`
const senderKid = 'did:webvh:def456:bob.test.example#k_senderhash'

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

function buildProjector(alreadyProcessed = autoMarkingAlreadyProcessed()) {
  return new DidCommIngressProjector({
    identityId, actorDeviceId: recipientKid,
    resolveOwnKey(kid) { return kid === recipientKid ? { kid: recipientKid, x25519PrivateKey: recipientX } : null },
    async resolveSenderKey(kid) { if (kid !== senderKid) throw new Error('unexpected sender kid ' + kid); return senderXPub },
    alreadyProcessed,
    async nextActorSeq() { return 1 },
    async initialParents() { return [] },
    activeSegment: segmentFor,
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
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
        expect(input.objects).toHaveLength(1)
        expect(input.events).toHaveLength(1)
        expect(input.events[0]!.kind).toBe('didcomm.control')
        expect(input.objects.map(o => o.objectId)).toEqual(input.events[0]!.objectRefs)

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

  test('a basicmessage from another agent\'s own did:peer:2 is a conversation with that did:peer', async () => {
    const mediator = generatePeerIdentity()
    const agent = generatePeerIdentity({ uri: 'https://agent-mediator.test.example', routingKeys: [mediator.xKid] })
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
    expect(result.projection.emails).toMatchObject([{ from: [{ email: agent.did }], to: [{ email: identityId }], threadId: didCommThreadId(identityId, agent.did) }])
  })

  test('a basicmessage addressed to several parties lands in the group thread its thid names, with every recipient in `to`', async () => {
    const carol = 'did:webvh:ghi789:carol.test.example'
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'hello, both of you', subject: 'Planning' }, didOfKid(senderKid), [identityId, carol], { thid: 'group-1' })
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const result = await buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.projection.emails).toMatchObject([{
      from: [{ email: didOfKid(senderKid) }], to: [{ email: identityId }, { email: carol }],
      threadId: didcommGroupAddress('group-1'), subject: 'Planning',
    }])
  })

  test('a group message that starts its own thread (no thid) is threaded by its id', async () => {
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'new group' }, didOfKid(senderKid), [identityId, 'did:webvh:ghi789:carol.test.example'], { id: 'first-message' })
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const result = await buildProjector().verifyAndProject(envelopeFor(new TextEncoder().encode(JSON.stringify(jwe))))
    expect(result.projection.emails[0]!.threadId).toBe(didcommGroupAddress('first-message'))
  })

  test('a group message that does not name this identity among its recipients is rejected', async () => {
    const plaintext = buildPlaintext(BASIC_MESSAGE, { content: 'not for you' }, didOfKid(senderKid), ['did:webvh:x:carol.test.example', 'did:webvh:y:dave.test.example'], { thid: 'group-2' })
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
        expect(input.objects).toHaveLength(2) // metadata + raw body, same shape as mail
        expect(input.events[0]!.kind).toBe('message.add')
        expect(input.projection).toMatchObject({
          emails: [{ from: [{ email: didOfKid(senderKid) }], to: [{ email: identityId }], threadId: didCommThreadId(identityId, didOfKid(senderKid)) }],
        })
        return 'committed'
      },
    })
    expect(result.ack.vaultEventId).toBeTruthy()
  })

  test('two different basicmessages between the same pair land in the SAME thread, chat-style (not per-subject like mail)', async () => {
    const projector = buildProjector()
    const first = buildPlaintext(BASIC_MESSAGE, { content: 'first message' }, didOfKid(senderKid))
    const firstJwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(first)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    let firstThreadId = ''
    await ingestIngress(envelopeFor(new TextEncoder().encode(JSON.stringify(firstJwe)), 'ingress-1'), signer, projector, {
      async commitIngress(input) { firstThreadId = (input.projection as { emails: Array<{ threadId: string }> }).emails[0]!.threadId; return 'committed' },
    })

    const second = buildPlaintext(BASIC_MESSAGE, { content: 'second message' }, didOfKid(senderKid))
    const secondJwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(second)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    let secondThreadId = ''
    await ingestIngress(envelopeFor(new TextEncoder().encode(JSON.stringify(secondJwe)), 'ingress-2'), signer, projector, {
      async commitIngress(input) { secondThreadId = (input.projection as { emails: Array<{ threadId: string }> }).emails[0]!.threadId; return 'committed' },
    })
    expect(firstThreadId).toBe(secondThreadId)
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
