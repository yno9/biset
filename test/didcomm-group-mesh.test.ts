// DIDComm group chat end to end (PLAN-refactor.md §8): real identities, a real
// (in-process) mediator. A group message is one Basic Message whose `to` lists
// every participant, sent to each of them on their own front door, encrypted
// for that participant alone. Every recipient device records it identically,
// so two devices of one identity merging their records through Vault Sync
// cannot make the projection rebuild fail (§9.1).
import { testWebvhResolver } from './support/mediator.ts'
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256Bytes } from '../src/protocol/canonical.ts'
import { acknowledgeMessages, pickupDeliver, type DeliveredMessage } from '../src/protocol/didcomm/mediator-pickup.ts'
import type { MediatorInboxClient, MediatorInfo } from '../src/protocol/didcomm/mediator-transport.ts'
import { mediatorInbox } from '../src/protocol/didcomm/mediator-device.ts'
import { registerWithMediator } from '../src/client/didcomm/mediator-sync.ts'
import { sendDidCommMessage } from '../src/client/didcomm/send-message.ts'
import { didcommGroupAddress } from '../src/client/didcomm/group-chat.ts'
import { DidCommIngressProjector } from '../src/client/didcomm/ingress-projector.ts'
import type { DidCommPlaintext } from '../src/protocol/didcomm/message.ts'
import type { IngressEnvelopeV1 } from '../src/protocol/ingress.ts'
import { createMediator } from '../src/server/mediator/server.ts'
import { SqliteMediatorStore } from '../src/server/mediator/sqlite-store.ts'
import { createSegmentKey, decryptVaultObject } from '../src/client/store/vault/objects.ts'
import { reduceLocalJmapProjection, type DecryptedMutationRecord } from '../src/client/store/projection/reducer.ts'
import type { VaultEventAuthor } from '../src/client/store/vault/events.ts'
import { buildDidCommLog } from './protocol/support/webvh-log-fixture.ts'

interface Device { kid: string; x: Uint8Array; secret: Uint8Array }
interface Identity { did: string; domain: string; devices: Device[]; log: unknown[] }

/** Pickup 3.0 keeps what it returns until acknowledged; ack it like a client. */
async function deliverAndAck(mediator: MediatorInfo, own: MediatorInboxClient, resolveSenderKey: Parameters<typeof pickupDeliver>[2], fetchImpl: typeof fetch): Promise<DeliveredMessage[]> {
  const delivered = await pickupDeliver(mediator, own, resolveSenderKey, 10, fetchImpl)
  if (delivered.length) await acknowledgeMessages(mediator, own, delivered.map(d => d.ackId), fetchImpl)
  return delivered
}

function makeIdentity(name: string, deviceCount: number, mediatorUrl: string, mediatorKid: string): Identity {
  const root = ed25519.utils.randomSecretKey()
  const domain = `${name}.test.example`
  const keys = Array.from({ length: deviceCount }, (_, index) => ({ fragment: `k_${name}-${index + 1}`, x: x25519.utils.randomSecretKey() }))
  const { did, log } = buildDidCommLog({
    rootPrivateKey: root, rootPublicKey: ed25519.getPublicKey(root),
    keyAgreementKeys: keys.map(key => ({ fragment: key.fragment, x25519PublicKey: x25519.getPublicKey(key.x) })),
    endpointUri: mediatorUrl, routingKeys: [mediatorKid], domain,
  })
  return { did, domain, log, devices: keys.map(key => ({ kid: `${did}#${key.fragment}`, x: key.x, secret: x25519.utils.randomSecretKey() })) }
}

const inboxOf = (identity: Identity, device: Device) => mediatorInbox({ did: identity.did, xKid: device.kid, xPriv: device.x }, device.secret)

/** What one device of `identity` records for a message it received. */
async function record(identity: Identity, device: Device, message: DeliveredMessage, senderX: Uint8Array): Promise<DecryptedMutationRecord> {
  const segmentKey = createSegmentKey()
  const signer: VaultEventAuthor = { deviceId: device.kid }
  const projector = new DidCommIngressProjector({
    identityId: identity.did, actorDeviceId: device.kid,
    resolveOwnKey: kid => kid === device.kid ? { kid, x25519PrivateKey: device.x } : null,
    resolveSenderKey: async () => x25519.getPublicKey(senderX),
    async alreadyProcessed() { return false },
    async nextActorSeq() { return 1 },
    async initialParents() { return [] },
    activeSegment: async () => ({ segmentId: `segment-${device.kid}`, segmentKey }),
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
    signer,
  })
  const payload = new TextEncoder().encode(JSON.stringify(message.rawJwe))
  const envelope: IngressEnvelopeV1 = {
    version: 1, ingressId: `ingress-${device.kid}`, protocol: 'didcomm', recipientIdentityId: identity.did, recipientDeviceSnapshot: [device.kid],
    createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), transportMetadata: {},
    sourceEvidence: new Uint8Array([1]), protectedPayload: payload, protectedPayloadHash: sha256Bytes(payload),
  }
  const result = await projector.verifyAndProject(envelope)
  return { event: result.events[0]!, plaintext: await decryptVaultObject(segmentKey, result.objects[0]!) }
}

describe('DIDComm group chat', () => {
  test('one message, addressed to every participant, reaches each on their front door; two devices of one recipient record it identically', async () => {
    const mediatorUrl = `https://group-mediator-${crypto.randomUUID()}.test.example`
    const store = SqliteMediatorStore.memory()
    const mediator = store.loadIdentity(mediatorUrl)
    const mediatorInfo: MediatorInfo = { url: mediatorUrl, did: mediator.did, xKid: mediator.xKid, xPub: mediator.xPub }

    const alice = makeIdentity('alice', 1, mediatorUrl, mediator.xKid)
    const bob = makeIdentity('bob', 2, mediatorUrl, mediator.xKid)
    const carol = makeIdentity('carol', 1, mediatorUrl, mediator.xKid)
    const identities = [alice, bob, carol]

    const webvh = testWebvhResolver()
    const { handle } = createMediator({ mediator, store, resolveWebvh: webvh.resolveWebvh })
    const fetchImpl = (async (input, init) => {
      const url = new URL(String(input))
      if (url.origin === mediatorUrl) return (await handle(new Request(url, init), url)) ?? new Response('not found', { status: 404 })
      const owner = identities.find(id => url.hostname === id.domain)
      if (url.pathname.endsWith('/did.jsonl') && owner) return new Response(owner.log.map(value => JSON.stringify(value)).join('\n') + '\n')
      return new Response(`unexpected request: ${url}`, { status: 500 })
    }) as typeof fetch
    webvh.useNetwork(fetchImpl)
    const realFetch = globalThis.fetch
    globalThis.fetch = fetchImpl
    try {
      for (const identity of identities) for (const device of identity.devices) await registerWithMediator(mediatorUrl, inboxOf(identity, device), fetchImpl)

      // Alice writes once to Bob and Carol: the same id, time, thread and audience to each.
      const aliceDevice = alice.devices[0]!
      const audience = [bob.did, carol.did]
      for (const to of audience) {
        const sent = await sendDidCommMessage(to, 'hello, both of you', {
          fromKid: aliceDevice.kid, x25519PrivateKey: aliceDevice.x, fetch: fetchImpl,
          id: 'msg-1', sentAt: '2026-10-07T00:10:00.000Z', thid: 'thread-1', audience, subject: 'Planning',
        })
        expect(sent).toEqual({ ok: true })
      }

      const fromAlice = async () => x25519.getPublicKey(aliceDevice.x)
      const bobCopies = await Promise.all(bob.devices.map(device => deliverAndAck(mediatorInfo, inboxOf(bob, device), fromAlice, fetchImpl)))
      const carolCopy = await deliverAndAck(mediatorInfo, inboxOf(carol, carol.devices[0]!), fromAlice, fetchImpl)
      for (const delivered of [...bobCopies, carolCopy]) {
        expect(delivered).toHaveLength(1)
        const plaintext = delivered[0]!.plaintext as DidCommPlaintext
        expect(plaintext.id).toBe('msg-1')
        expect(plaintext.thid).toBe('thread-1')
        expect(plaintext.from).toBe(alice.did)
        expect(plaintext.to).toEqual(audience)
        expect(delivered[0]!.senderKid).toBe(aliceDevice.kid)
      }

      // Each of Bob's devices records its own copy; merged (as Vault Sync
      // does), the rebuild accepts both as the one same message.
      const records = await Promise.all(bob.devices.map((device, index) => record(bob, device, bobCopies[index]![0]!, aliceDevice.x)))
      const merged = reduceLocalJmapProjection(bob.did, { mailboxes: [], emails: [], contactCards: [] }, records)
      expect(merged.emails).toHaveLength(1)
      expect(merged.emails[0]).toMatchObject({
        threadId: didcommGroupAddress('thread-1'), subject: 'Planning',
        from: [{ email: alice.did }], to: [{ email: bob.did }, { email: carol.did }],
      })

      // Carol files it under the same conversation.
      const carolRecord = await record(carol, carol.devices[0]!, carolCopy[0]!, aliceDevice.x)
      expect(reduceLocalJmapProjection(carol.did, { mailboxes: [], emails: [], contactCards: [] }, [carolRecord]).emails[0]!.threadId).toBe(didcommGroupAddress('thread-1'))
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
