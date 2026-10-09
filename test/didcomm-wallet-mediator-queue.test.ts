// Regression coverage for the did.md Wallet account's mediator delivery
// handler (main.ts's handleWalletDidCommMessage).
//
// Besides Vault Sync, the Wallet branch has exactly one branch for a
// delivered message: hand it to DidCommIngressProjector. That projector
// throws for every type it cannot project, and watchMediatorLive deliberately
// does NOT acknowledge a message whose onMessage threw -- so before the guard
// added alongside these tests, a single message of an unsupported type (then
// a group invite; now, say, the retired relationship INIT a not-yet-updated
// device may still send) stayed queued at the mediator forever and was
// re-delivered, and re-failed, on every reconnect.
//
// The first test below pins the projector's own allow-list against
// isProjectableDidCommIngress (the guard must never drift from what the
// projector actually accepts); the last two drive a real mediator + a real
// watchMediatorLive and assert the queue state directly, once with the
// pre-guard handler shape (the bug, still queued) and once with the shipped
// shape (acknowledged, queue empty).
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { sha256Bytes } from '../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../src/protocol/ingress.ts'
import { packAuthcrypt, packAnoncrypt, didCommPost } from '../src/protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../src/protocol/didcomm/message.ts'
import { PING } from '../src/protocol/didcomm/trust-ping.ts'
import { BASIC_MESSAGE } from '../src/client/didcomm/basicmessage.ts'
// Types this endpoint no longer projects: the retired relationship handshake
// and group protocol (PLAN-refactor.md §3, §8).
const RETIRED_INIT = 'https://biset.md/relationship/1.0/init'
const RETIRED_GROUP_INVITE = 'https://biset.md/didcomm-group/1.0/invite'
import { PROBLEM_REPORT } from '../src/protocol/didcomm/problems.ts'
import { DidCommIngressProjector, isProjectableDidCommIngress } from '../src/client/didcomm/ingress-projector.ts'
import { generatePeerIdentity } from '../src/protocol/didcomm/peer.ts'
import { registerWithMediator } from '../src/client/didcomm/mediator-sync.ts'
import { pickupStatus, type DeliveredMessage } from '../src/protocol/didcomm/mediator-pickup.ts'
import { watchMediatorLive } from '../src/client/didcomm/mediator-live.ts'
import { freshMediatorFetch } from './support/mediator.ts'
import type { MediatorInboxClient } from '../src/protocol/didcomm/mediator-transport.ts'
import { createSegmentKey } from '../src/client/store/vault/objects.ts'
import type { VaultEventAuthor } from '../src/client/store/vault/events.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const identityId = 'did:webvh:abc123:wallet.test.example'
const recipientKid = `${identityId}#k_walletdevice`

const signer: VaultEventAuthor = { deviceId: recipientKid }
const segmentKey = createSegmentKey()
async function segmentFor() {
  return { segmentId: 'segment-1', segmentKey }
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
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
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
    // An authcrypt message must name its sender in `from`, matching the skid (DIDComm v2.1).
    const plaintext = buildPlaintext(type, {}, senderKid.split('#', 1)[0])
    const jwe = packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: recipientXPub }])
    const projector = buildProjector({ kid: recipientKid, x25519PrivateKey: recipientX }, senderKid, senderXPub)
    try {
      await projector.verifyAndProject(envelopeFor(utf8(JSON.stringify(jwe)), `ingress-${type}`))
      return null
    } catch (error) {
      return error instanceof Error ? error.message : String(error)
    }
  }

  for (const type of [RETIRED_INIT, RETIRED_GROUP_INVITE]) {
    test(`${type} is not projectable, and the projector agrees`, async () => {
      expect(isProjectableDidCommIngress({ type })).toBe(false)
      expect(await projectType(type)).toBe(`unsupported DIDComm message type for this endpoint slice: ${type}`)
    })
  }

  // ... and the guard must not over-drop: everything the projector DOES
  // handle has to pass it. (A ping projects cleanly; the others get past the
  // type check and fail later, on their deliberately empty body -- which is
  // exactly the proof that the type check let them through.)
  test('ping / basicmessage / problem-report stay projectable', async () => {
    for (const type of [PING, BASIC_MESSAGE, PROBLEM_REPORT]) {
      expect(isProjectableDidCommIngress({ type })).toBe(true)
      expect(await projectType(type)).not.toBe(`unsupported DIDComm message type for this endpoint slice: ${type}`)
    }
    expect(await projectType(PING)).toBeNull()
    expect(await projectType(PROBLEM_REPORT)).toBeNull()
  })
})

/** Delivers one authcrypt'd message of `type` into bob's mediator queue. */
async function forwardToWallet(fetchImpl: typeof fetch, mediatorUrl: string, mediatorXKid: string, mediatorXPub: Uint8Array,
  alice: ReturnType<typeof generatePeerIdentity>, bob: MediatorInboxClient, bobXPub: Uint8Array, type: string, body: Record<string, unknown>) {
  const inner = buildPlaintext(type, body, alice.did, bob.did)
  const innerJwe = packAuthcrypt(utf8(JSON.stringify(inner)), { kid: alice.xKid, privateKey: alice.xPriv }, [{ kid: bob.xKid, publicKey: bobXPub }])
  const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.xKid })
  forward.attachments = [{ id: 'inner', data: { json: innerJwe } }]
  const forwardJwe = packAnoncrypt(utf8(JSON.stringify(forward)), [{ kid: mediatorXKid, publicKey: mediatorXPub }])
  const res = await fetchImpl(`${mediatorUrl}/`, didCommPost(forwardJwe))
  expect(res.status).toBe(202)
}

/**
 * Runs one message of a retired type through a real mediator queue and a real
 * watchMediatorLive, with a handler shaped exactly like the Wallet branch's
 * handleWalletDidCommMessage -- `guard: false` is the pre-fix shape (every
 * delivery goes straight to the projector), `guard: true` is the shipped
 * one. Returns how many messages the mediator still has queued afterwards.
 */
async function walletDeliveryLeavesQueued(guard: boolean): Promise<{ queued: number; handlerErrors: string[] }> {
  const { fetchImpl, url, webSocketCtor } = freshMediatorFetch()
  const alicePeer = generatePeerIdentity()
  const bobPeer = generatePeerIdentity()
  const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
  const info = await registerWithMediator(url, bob, fetchImpl)
  await forwardToWallet(fetchImpl, url, info.xKid, info.xPub, alicePeer, bob, bobPeer.xPub,
    RETIRED_INIT, { relationshipKid: alicePeer.xKid, publicKey: 'AA' })

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

  const watch = watchMediatorLive({
    mediatorUrl: url, inbox: bob, resolveSenderKey: async () => alicePeer.xPub,
    onMessage, onError: () => {},
    fetch: fetchImpl, webSocketCtor,
  })
  const deadline = Date.now() + 3000
  while (handled === 0 && Date.now() < deadline) await new Promise(r => setTimeout(r, 10))
  // The acknowledgement watchMediatorLive sends after a successful onMessage is
  // a separate round trip -- give it a beat to land before reading status.
  await new Promise(r => setTimeout(r, 50))
  watch.close()
  return { queued: (await pickupStatus(info, bob, fetchImpl)).messageCount, handlerErrors }
}

describe('did.md Wallet mediator delivery handler', () => {
  test('the pre-guard handler shape leaves an unsupported message queued forever (the bug)', async () => {
    const { queued, handlerErrors } = await walletDeliveryLeavesQueued(false)
    expect(handlerErrors).toEqual([`unsupported DIDComm message type for this endpoint slice: ${RETIRED_INIT}`])
    // watchMediatorLive never acked it: the very same message comes back on the
    // next reconnect, and fails identically, forever.
    expect(queued).toBe(1)
  })

  test('the shipped handler drops an unsupported type and lets the queue drain', async () => {
    const { queued, handlerErrors } = await walletDeliveryLeavesQueued(true)
    expect(handlerErrors).toEqual([])
    expect(queued).toBe(0)
  })
})

// The Wallet path's guard is the only mediator delivery handler left in
// main.ts: the local-identity (seed) boot path that carried the second copy
// of it was removed in N1 (2026-09-05). What this pins is that the guard
// still calls the projector's own exported allow-list rather than a
// hand-maintained list of its own that could drift from it.
//
// Source-level, for the same reason wallet-vault-sync-timeout.test.ts is:
// the handler is declared inside a closure in the browser entry point and
// has no importable seam. The behaviour it produces is already covered
// above against a real mediator.
const mainSource = await Bun.file(new URL('../src/client/app/main.ts', import.meta.url)).text()
const projectorSource = await Bun.file(new URL('../src/client/didcomm/ingress-projector.ts', import.meta.url)).text()

describe('mediator delivery handler (main.ts)', () => {
  test('the account path shares one allow-list with the projector', () => {
    expect(projectorSource).toContain('export function isProjectableDidCommIngress')
    expect(projectorSource).toContain('if (!isProjectableDidCommIngress(msg)) throw')
    expect(mainSource).toContain('isProjectableDidCommIngress(')
  })
})
