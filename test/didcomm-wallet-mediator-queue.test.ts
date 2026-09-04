// Regression coverage for the did.md Wallet account's mediator delivery
// handler (main.ts's handleWalletDidCommMessage).
//
// The Wallet branch has exactly one branch for a delivered message: hand it
// to DidCommIngressProjector. That projector throws for every type outside
// ping/basicmessage/relationship, and watchMediator deliberately does NOT
// acknowledge a message whose onMessage threw -- so before the guard added
// alongside these tests, a single GROUP_INVITE (or GROUP_MESSAGE, or
// MAIL_BRIDGE_INBOUND) addressed to a Wallet account stayed queued at the
// mediator forever and was re-delivered, and re-failed, on every reconnect.
//
// The first test below pins the projector's own allow-list against
// isProjectableDidCommIngress (the guard must never drift from what the
// projector actually accepts); the last two drive a real mediator + a real
// watchMediator and assert the queue state directly, once with the
// pre-guard handler shape (the bug, still queued) and once with the shipped
// shape (acknowledged, queue empty).
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { equalBytes, sha256Bytes } from '../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../src/protocol/ingress.ts'
import { packAuthcrypt, packAnoncrypt } from '../src/didcomm/crypto.ts'
import { buildPlaintext } from '../src/didcomm/message.ts'
import { PING } from '../src/didcomm/trust-ping.ts'
import { BASIC_MESSAGE } from '../src/didcomm/basicmessage.ts'
import { RELATIONSHIP_ACCEPT, RELATIONSHIP_INIT } from '../src/didcomm/relationship.ts'
import { GROUP_INVITE, GROUP_MESSAGE } from '../src/didcomm/group-chat.ts'
import { MAIL_BRIDGE_INBOUND } from '../src/didcomm/mail-bridge.ts'
import { DidCommIngressProjector, isProjectableDidCommIngress } from '../src/didcomm/ingress-projector.ts'
import { generatePeerIdentity } from '../src/didcomm/peer.ts'
import { createMediator } from '../src/mediator/server.ts'
import { registerWithMediator } from '../src/didcomm/mediator-sync.ts'
import { pickupStatus, type DeliveredMessage } from '../src/didcomm/mediator-pickup.ts'
import { watchMediator } from '../src/didcomm/mediator-watch.ts'
import type { DidCommSender } from '../src/didcomm/mediator-transport.ts'
import { createSegmentKeyWrap } from '../src/vault/crypto.ts'
import { createSegmentKey } from '../src/vault/objects.ts'
import type { VaultEventSigner } from '../src/vault/events.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const identityId = 'did:webvh:abc123:wallet.test.example'
const recipientKid = `${identityId}#k_walletdevice`

const signer: VaultEventSigner = {
  deviceId: recipientKid,
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === recipientKid && equalBytes(signature, await this.sign(bytes)) },
}
const segmentKey = createSegmentKey()
async function segmentFor() {
  const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(9), segmentKey, {
    identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1',
    grantorDeviceId: recipientKid, grantedAt: '2026-09-05T00:00:00.000Z',
  }, signer)
  return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] }
}

function buildProjector(own: { kid: string; x25519PrivateKey: Uint8Array }, senderKid: string, senderXPub: Uint8Array) {
  return new DidCommIngressProjector({
    identityId, actorDeviceId: recipientKid,
    resolveOwnKey(kid) { return kid === own.kid ? own : null },
    async resolveSenderKey(kid) { if (kid !== senderKid) throw new Error(`unexpected sender kid ${kid}`); return senderXPub },
    async alreadyProcessed() { return false },
    async nextActorSeq() { return 1 },
    async initialParents() { return [] },
    activeSegment: segmentFor,
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [] } },
    signer,
    now: () => new Date('2026-09-05T00:01:00.000Z'),
  })
}

function envelopeFor(payload: Uint8Array, ingressId: string): IngressEnvelopeV1 {
  return {
    version: 1, ingressId, protocol: 'didcomm', recipientIdentityId: identityId, recipientDeviceSnapshot: [recipientKid],
    createdAt: '2026-09-05T00:00:00.000Z', expiresAt: '2026-09-06T00:00:00.000Z', transportMetadata: {},
    sourceEvidence: new Uint8Array([1]), protectedPayload: payload, protectedPayloadHash: sha256Bytes(payload),
  }
}

describe('DidCommIngressProjector allow-list (isProjectableDidCommIngress)', () => {
  const senderX = x25519.utils.randomSecretKey()
  const senderXPub = x25519.getPublicKey(senderX)
  const senderKid = 'did:webvh:def456:bob.test.example#k_sender'
  const recipientX = x25519.utils.randomSecretKey()
  const recipientXPub = x25519.getPublicKey(recipientX)

  async function projectType(type: string): Promise<string | null> {
    const plaintext = buildPlaintext(type, {})
    const jwe = packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, { kid: recipientKid, publicKey: recipientXPub })
    const projector = buildProjector({ kid: recipientKid, x25519PrivateKey: recipientX }, senderKid, senderXPub)
    try {
      await projector.verifyAndProject(envelopeFor(utf8(JSON.stringify(jwe)), `ingress-${type}`))
      return null
    } catch (error) {
      return error instanceof Error ? error.message : String(error)
    }
  }

  // The three types a Wallet account can actually receive today but has no
  // branch for. Each MUST be rejected by the guard, because the projector
  // itself rejects it with the very message quoted here.
  for (const type of [GROUP_INVITE, GROUP_MESSAGE, MAIL_BRIDGE_INBOUND]) {
    test(`${type} is not projectable, and the projector agrees`, async () => {
      expect(isProjectableDidCommIngress({ type })).toBe(false)
      expect(await projectType(type)).toBe(`unsupported DIDComm message type for this endpoint slice: ${type}`)
    })
  }

  // ... and the guard must not over-drop: everything the projector DOES
  // handle has to pass it. (A ping projects cleanly; the two relationship
  // types get past the type check and fail later, on their deliberately
  // empty body -- which is exactly the proof that the type check let them
  // through. Basic Message likewise gets past the type check.)
  test('ping / basicmessage / relationship stay projectable', async () => {
    for (const type of [PING, BASIC_MESSAGE, RELATIONSHIP_INIT, RELATIONSHIP_ACCEPT]) {
      expect(isProjectableDidCommIngress({ type })).toBe(true)
      expect(await projectType(type)).not.toBe(`unsupported DIDComm message type for this endpoint slice: ${type}`)
    }
    expect(await projectType(PING)).toBeNull()
  })
})

/** A fresh, unique mediator URL per call -- fetchMediatorInfo caches per URL. */
function freshMediatorFetch() {
  const url = `https://mediator-${crypto.randomUUID()}.test.example`
  const mediator = generatePeerIdentity({ uri: url, accept: ['didcomm/v2'] })
  const { handle } = createMediator({ mediator })
  const fetchImpl: typeof fetch = async (input, init) => {
    const reqUrl = new URL(String(input))
    const res = await handle(new Request(reqUrl, init), reqUrl)
    return res ?? new Response('not found', { status: 404 })
  }
  return { fetchImpl, url }
}

/** Same shape mediator-client.test.ts reads SSE frames with. */
function sseFrameReader(response: Response) {
  const reader = response.body!.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  return {
    async next(count: number, deadlineMs = 2000): Promise<Array<{ id: string; jwe: unknown }>> {
      const frames: Array<{ id: string; jwe: unknown }> = []
      const deadline = Date.now() + deadlineMs
      while (frames.length < count && Date.now() < deadline) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        let sep: number
        while ((sep = buffer.indexOf('\n\n')) !== -1) {
          const raw = buffer.slice(0, sep)
          buffer = buffer.slice(sep + 2)
          const line = raw.split('\n').find(l => l.startsWith('data: '))
          if (line) frames.push(JSON.parse(line.slice('data: '.length)))
        }
      }
      return frames
    },
    async close(): Promise<void> { await reader.cancel().catch(() => {}) },
  }
}

/** Delivers one authcrypt'd message of `type` into bob's mediator queue. */
async function forwardToWallet(fetchImpl: typeof fetch, mediatorUrl: string, mediatorXKid: string, mediatorXPub: Uint8Array,
  alice: ReturnType<typeof generatePeerIdentity>, bob: DidCommSender, bobXPub: Uint8Array, type: string, body: Record<string, unknown>) {
  const inner = buildPlaintext(type, body, alice.did, bob.did)
  const innerJwe = packAuthcrypt(utf8(JSON.stringify(inner)), { kid: alice.xKid, privateKey: alice.xPriv }, { kid: bob.xKid, publicKey: bobXPub })
  const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.xKid })
  forward.attachments = [{ id: 'inner', data: { json: innerJwe } }]
  const forwardJwe = packAnoncrypt(utf8(JSON.stringify(forward)), { kid: mediatorXKid, publicKey: mediatorXPub })
  const res = await fetchImpl(`${mediatorUrl}/`, { method: 'POST', body: JSON.stringify(forwardJwe) })
  expect(res.status).toBe(202)
}

/**
 * Runs one GROUP_INVITE through a real mediator queue and a real
 * watchMediator, with a handler shaped exactly like the Wallet branch's
 * handleWalletDidCommMessage -- `guard: false` is the pre-fix shape (every
 * delivery goes straight to the projector), `guard: true` is the shipped
 * one. Returns how many messages the mediator still has queued afterwards.
 */
async function walletDeliveryLeavesQueued(guard: boolean): Promise<{ queued: number; handlerErrors: string[] }> {
  const { fetchImpl, url } = freshMediatorFetch()
  const alicePeer = generatePeerIdentity()
  const bobPeer = generatePeerIdentity()
  const bob: DidCommSender = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }
  const info = await registerWithMediator(url, bob, fetchImpl)
  await forwardToWallet(fetchImpl, url, info.xKid, info.xPub, alicePeer, bob, bobPeer.xPub,
    GROUP_INVITE, { groupId: 'g-1', members: [alicePeer.did, bobPeer.did] })

  class FakeEventSource {
    onmessage: ((event: { data: string }) => void) | null = null
    onerror: (() => void) | null = null
    private closed = false
    constructor(public readonly streamUrl: string) { void this.pump() }
    private async pump(): Promise<void> {
      const response = await fetchImpl(this.streamUrl, { method: 'GET' })
      const [frame] = await sseFrameReader(response).next(1)
      if (this.closed || !frame) return
      this.onmessage?.({ data: JSON.stringify(frame) })
    }
    close(): void { this.closed = true }
  }

  const handlerErrors: string[] = []
  let handled = 0
  // handleWalletDidCommMessage, reduced to the part under test.
  const onMessage = async (msg: DeliveredMessage): Promise<void> => {
    try {
      const plaintext = msg.plaintext as { type?: string }
      if (guard && !isProjectableDidCommIngress(plaintext)) return
      const payload = utf8(JSON.stringify(msg.rawJwe))
      const projector = buildProjector({ kid: bob.xKid, x25519PrivateKey: bob.xPriv }, msg.senderKid, alicePeer.xPub)
      await projector.verifyAndProject(envelopeFor(payload, `ingress-${msg.ackId}`))
    } catch (error) {
      handlerErrors.push(error instanceof Error ? error.message : String(error))
      throw error
    } finally {
      handled += 1
    }
  }

  const watch = watchMediator({
    mediatorUrl: url, own: bob, resolveSenderKey: async () => alicePeer.xPub,
    onMessage, onError: () => {},
    fetch: fetchImpl, eventSourceCtor: FakeEventSource as unknown as typeof EventSource,
  })
  const deadline = Date.now() + 3000
  while (handled === 0 && Date.now() < deadline) await new Promise(r => setTimeout(r, 10))
  // The acknowledgement watchMediator sends after a successful onMessage is
  // a separate round trip -- give it a beat to land before reading status.
  await new Promise(r => setTimeout(r, 50))
  watch.close()
  return { queued: await pickupStatus(info, bob, fetchImpl), handlerErrors }
}

describe('did.md Wallet mediator delivery handler', () => {
  test('the pre-guard handler shape leaves a GROUP_INVITE queued forever (the bug)', async () => {
    const { queued, handlerErrors } = await walletDeliveryLeavesQueued(false)
    expect(handlerErrors).toEqual([`unsupported DIDComm message type for this endpoint slice: ${GROUP_INVITE}`])
    // watchMediator never acked it: the very same message comes back on the
    // next reconnect, and fails identically, forever.
    expect(queued).toBe(1)
  })

  test('the shipped handler drops an unsupported type and lets the queue drain', async () => {
    const { queued, handlerErrors } = await walletDeliveryLeavesQueued(true)
    expect(handlerErrors).toEqual([])
    expect(queued).toBe(0)
  })
})
