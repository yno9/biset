// End-to-end: a real MLS application message (alice -> bob, via
// group.ts/conversation-group.ts, submitted through a real Conversation
// Group DS) wrapped in a real message-notify DIDComm envelope (authcrypt,
// exactly the shape mls-ds/fanout.ts builds), decrypted and projected by
// ConversationGroupIngressProjector -- confirms the whole receive path
// (JWE unpack -> MLS decrypt -> MimiContent decode -> Vault mutation)
// actually interoperates, mirroring didcomm-ingress-projector.test.ts's
// shape for 1:1 chat.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url, equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { packAuthcrypt } from '../../src/didcomm/crypto.ts'
import { buildPlaintext } from '../../src/didcomm/message.ts'
import { PING } from '../../src/didcomm/trust-ping.ts'
import { MESSAGE_NOTIFY } from '../../src/mls-ds/didcomm-types.ts'
import { SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'
import { Ed25519ConversationDsSignatureVerifier } from '../../src/mls-ds/authorizer.ts'
import { createConversationDeliveryHttpHandler } from '../../src/mls-ds/http.ts'
import { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'
import { ConversationGroupIngressProjector, DidCommReplayError } from '../../src/mls/conversation-group-ingress.ts'
import type { MlsConversationGroupStateStore } from '../../src/mls/conversation-group-store.ts'
import { addMembersToConversationGroup, createConversationGroup, sendConversationApplicationMessage } from '../../src/mls/conversation-group.ts'
import { joinMlsGroup, type ClientState } from '../../src/mls/group.ts'
import { computeMimiMessageId, encodeMimiContent, mimiRoomUri, DISPOSITION_RENDER, type MimiContent } from '../../src/mls/mimi-content.ts'
import { messageIdToEmailId } from '../../src/mls/mimi-content-projector.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import { createSegmentKey, decryptVaultObject } from '../../src/vault/objects.ts'
import { decodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { ingestIngress } from '../../src/vault/ingress-ingest.ts'
import { mlsDeviceFixture } from '../protocol/support/mls-device-fixture.ts'

const identityId = 'did:web:bob.example'
const recipientKid = `${identityId}#k_devicehash`
const dsKid = 'did:web:mls-ds.example#k_ds'

const signer: VaultEventSigner = {
  deviceId: recipientKid,
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === recipientKid && equalBytes(signature, await this.sign(bytes)) },
}

const dsX = x25519.utils.randomSecretKey()
const dsXPub = x25519.getPublicKey(dsX)
const recipientX = x25519.utils.randomSecretKey()
const recipientXPub = x25519.getPublicKey(recipientX)

const segmentKey = createSegmentKey()
async function segmentFor() {
  const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(9), segmentKey, {
    identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: recipientKid, grantedAt: '2026-08-31T00:00:00.000Z',
  }, signer)
  return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] }
}

function envelopeFor(payload: Uint8Array, ingressId = 'ingress-1'): IngressEnvelopeV1 {
  return {
    version: 1, ingressId, protocol: 'didcomm', recipientIdentityId: identityId, recipientDeviceSnapshot: [recipientKid],
    createdAt: '2026-08-31T00:00:00.000Z', expiresAt: '2026-09-01T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([1]),
    protectedPayload: payload, protectedPayloadHash: sha256Bytes(payload),
  }
}

function memoryStateStore(initial?: { groupId: string; state: ClientState; lastSeenSeq: number }): MlsConversationGroupStateStore {
  const rows = new Map<string, { state: ClientState; lastSeenSeq: number }>()
  if (initial) rows.set(initial.groupId, { state: initial.state, lastSeenSeq: initial.lastSeenSeq })
  return {
    async save(groupId, state, lastSeenSeq) { rows.set(groupId, { state, lastSeenSeq }) },
    async load(groupId) { return rows.get(groupId) },
    async listGroupIds() { return [...rows.keys()] },
  }
}

function buildProjector(stateStore: MlsConversationGroupStateStore) {
  return new ConversationGroupIngressProjector({
    identityId, actorDeviceId: recipientKid,
    resolveOwnKey(kid) { return kid === recipientKid ? { kid: recipientKid, x25519PrivateKey: recipientX } : null },
    async resolveSenderKey(kid) { if (kid !== dsKid) throw new Error('unexpected sender kid ' + kid); return dsXPub },
    async nextActorSeq() { return 1 },
    async initialParents() { return [] },
    activeSegment: segmentFor,
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [] } },
    stateStore,
    signer,
    now: () => new Date('2026-08-31T00:01:00.000Z'),
  })
}

function messageNotifyJwe(body: unknown, dsSenderKid = dsKid, dsSenderKey = dsX) {
  const plaintext = buildPlaintext(MESSAGE_NOTIFY, body as Record<string, unknown>)
  return packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: dsSenderKid, privateKey: dsSenderKey }, { kid: recipientKid, publicKey: recipientXPub })
}

const sqlitePaths: string[] = []
afterEach(() => {
  for (const path of sqlitePaths.splice(0)) {
    for (const suffix of ['', '-wal', '-shm']) { try { rmSync(`${path}${suffix}`) } catch {} }
  }
})

/** A real 2-member Conversation Group (alice, bob) over the real DS HTTP
 * handler: alice creates it, adds bob, bob joins from the Welcome, alice
 * sends one MimiContent application message -- returns the exact
 * message-notify body mls-ds/fanout.ts would have built for it, plus bob's
 * own post-join ClientState for the projector to decrypt against. */
async function setupDeliveredMessage(text: string) {
  const path = `/tmp/biset-conversation-group-ingress-${process.pid}-${Date.now()}-${Math.random()}.sqlite`
  sqlitePaths.push(path)
  const alice = await mlsDeviceFixture('did:web:alice.example')
  const bobMls = await mlsDeviceFixture(identityId)
  const ds = SqliteConversationDeliveryService.open(path)
  const verifier = new Ed25519ConversationDsSignatureVerifier({
    async resolveEd25519PublicKey(kid) {
      if (kid === alice.kid) return alice.own.publicPackage.leafNode.signaturePublicKey
      if (kid === bobMls.kid) return bobMls.own.publicPackage.leafNode.signaturePublicKey
      return undefined
    },
  })
  const handle = createConversationDeliveryHttpHandler(ds, verifier)
  const transport = new ConversationMlsDeliveryTransport({ baseUrl: 'https://mls-ds.example', deviceCredential: new Uint8Array([1]), fetch: (input, init) => handle(new Request(input, init)) })
  const aliceSign = (bytes: Uint8Array) => ed25519.sign(bytes, alice.own.privatePackage.signaturePrivateKey)

  const groupId = `group-ingress-${Math.random().toString(16).slice(2)}`
  let aliceState = await createConversationGroup(transport, groupId, alice.kid, alice.own, aliceSign)
  aliceState = await addMembersToConversationGroup(aliceState, transport, groupId, alice.kid, [bobMls.own.publicPackage], [bobMls.kid], aliceSign)
  const welcomeEntry = ds.deliveriesSince(groupId, bobMls.kid, 0)!.find(e => e.kind === 'welcome')!
  const bobState = await joinMlsGroup(welcomeEntry.payload, bobMls.own, undefined)
  const beforeSend = ds.deliveriesSince(groupId, bobMls.kid, 0)!.length

  const senderUri = alice.kid
  const roomUri = mimiRoomUri(groupId)
  const content: MimiContent = {
    salt: new Uint8Array(16).fill(3), replaces: null, topicId: new Uint8Array(0), expires: null, inReplyTo: null,
    extensions: { senderUri, roomUri },
    nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode(text) } },
  }
  const encoded = encodeMimiContent(content)
  const messageId = await computeMimiMessageId(senderUri, roomUri, encoded, content.salt)
  aliceState = await sendConversationApplicationMessage(aliceState, transport, groupId, alice.kid, encoded, aliceSign)

  const entries = ds.deliveriesSince(groupId, bobMls.kid, beforeSend)!
  const applicationEntry = entries.find(e => e.kind === 'application')!
  ds.close()

  const body = { groupId, seq: applicationEntry.seq, epoch: applicationEntry.epoch, privateMessage: bytesToBase64url(applicationEntry.payload), at: applicationEntry.at }
  return { groupId, body, bobState, messageId, content, senderKid: alice.kid }
}

describe('ConversationGroupIngressProjector', () => {
  test('a message-notify decrypts (DIDComm + MLS) and lands as a message.add email attributed to the MLS-authenticated sender', async () => {
    const { groupId, body, bobState, messageId, senderKid } = await setupDeliveredMessage('hello group')
    const stateStore = memoryStateStore({ groupId, state: bobState, lastSeenSeq: 0 })
    const projector = buildProjector(stateStore)
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(messageNotifyJwe(body))))

    const result = await ingestIngress(envelope, signer, projector, {
      async commitIngress(input) {
        expect(input.objects).toHaveLength(2) // metadata + raw body, same shape as basicmessage/mail
        expect(input.events[0]!.kind).toBe('message.add')
        expect(input.projection).toMatchObject({
          emails: [{ id: messageIdToEmailId(messageId), from: [{ email: senderKid }], to: [{ email: identityId }], threadId: groupId }],
        })
        const plaintextObject = await decryptVaultObject(segmentKey, input.objects[0]!)
        const decoded = JSON.parse(new TextDecoder().decode(plaintextObject)) as { payload: { email: { id: string } } }
        expect(decoded.payload.email.id).toBe(messageIdToEmailId(messageId))
        const raw = await decryptVaultObject(segmentKey, input.objects[1]!)
        expect(new TextDecoder().decode(raw)).toBe('hello group')
        return 'committed'
      },
    })
    expect(result.ack.vaultEventId).toBeTruthy()

    const stored = await stateStore.load(groupId)
    expect(stored?.lastSeenSeq).toBe(body.seq)
  })

  test('a message-notify with seq <= the stored cursor is rejected as a replay, not re-decrypted', async () => {
    const { groupId, body, bobState } = await setupDeliveredMessage('already seen')
    const stateStore = memoryStateStore({ groupId, state: bobState, lastSeenSeq: body.seq })
    const projector = buildProjector(stateStore)
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(messageNotifyJwe(body))))
    await expect(projector.verifyAndProject(envelope)).rejects.toBeInstanceOf(DidCommReplayError)
  })

  test('a message-notify for a group this device has no local state for is rejected, not silently dropped', async () => {
    const { body } = await setupDeliveredMessage('no local state')
    const projector = buildProjector(memoryStateStore())
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(messageNotifyJwe(body))))
    await expect(projector.verifyAndProject(envelope)).rejects.toThrow(/no local state/)
  })

  test('a non-message-notify DIDComm type is rejected', async () => {
    const { groupId, bobState } = await setupDeliveredMessage('irrelevant')
    const stateStore = memoryStateStore({ groupId, state: bobState, lastSeenSeq: 0 })
    const projector = buildProjector(stateStore)
    const plaintext = buildPlaintext(PING, { response_requested: true })
    const jwe = packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: dsKid, privateKey: dsX }, { kid: recipientKid, publicKey: recipientXPub })
    const envelope = envelopeFor(new TextEncoder().encode(JSON.stringify(jwe)))
    await expect(projector.verifyAndProject(envelope)).rejects.toThrow(/unsupported DIDComm message type/)
  })
})
