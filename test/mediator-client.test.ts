// End-to-end coverage for the CLIENT side of the standalone mediator
// protocol (src/protocol/didcomm/mediator-{transport,coordinate,pickup,sync}.ts,
// ARC.md's 2026-08-27 redesign, Phase 4) -- driven against the same
// createMediator handler Phase 3's test exercises directly, but this time
// entirely through the client library a real device would use. The
// mediator's HTTP surface is faked as a fetch that dispatches straight into
// the in-process handler, so this is a real protocol round trip with no
// network.
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../src/protocol/didcomm/peer.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist, queryKeylist } from '../src/protocol/didcomm/mediator-coordinate.ts'
import { pickupStatus, pickupDeliver, acknowledgeMessages } from '../src/protocol/didcomm/mediator-pickup.ts'
import { MediatorDeviceLimitError, registerWithMediator, startMediatorPolling } from '../src/client/didcomm/mediator-sync.ts'
import { watchMediatorLive } from '../src/client/didcomm/mediator-live.ts'
import { packMediatorRequest, unpackMediatorMessage } from '../src/protocol/didcomm/mediator-transport.ts'
import { DELIVERY, LIVE_DELIVERY_CHANGE, LIVE_MODE_NOT_SUPPORTED_PROBLEM, STATUS } from '../src/protocol/didcomm/mediator-protocol.ts'
import { PING, PING_RESPONSE } from '../src/protocol/didcomm/trust-ping.ts'
import { createMediatorDeployment } from '../src/server/mediator/deployment.ts'
import type { LiveSocket, MediatorHandler } from '../src/server/mediator/server.ts'
import { freshMediatorFetch } from './support/mediator.ts'
import type { DidCommPlaintext } from '../src/protocol/didcomm/message.ts'
import type { MediatorInboxClient } from '../src/protocol/didcomm/mediator-transport.ts'
import { packAuthcrypt, packAnoncrypt, didCommPost } from '../src/protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../src/protocol/didcomm/message.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)

/** A raw live socket into `live`, collecting what the mediator pushes. */
function rawLiveSocket(live: MediatorHandler['live']) {
  const frames: string[] = []
  const socket: LiveSocket = { send: data => { frames.push(data) } }
  return { socket, frames, send: (raw: unknown) => live.message(socket, JSON.stringify(raw)) }
}

async function until(condition: () => boolean, deadlineMs = 2000): Promise<void> {
  const deadline = Date.now() + deadlineMs
  while (!condition() && Date.now() < deadline) await new Promise(r => setTimeout(r, 5))
}

/** Simulates what Phase 5's send-message.ts will build: alice authcrypts to
 * bob's kid, then anoncrypts a Forward naming it as `next` to the
 * mediator's own kid, and delivers it straight into the mediator (there is
 * no sender-side client library yet -- that is Phase 5). */
async function forwardFromAliceToBob(fetchImpl: typeof fetch, mediatorUrl: string, mediatorXKid: string, mediatorXPub: Uint8Array, alice: ReturnType<typeof generatePeerIdentity>, bob: MediatorInboxClient, bobXPub: Uint8Array, content: string) {
  const inner = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content }, alice.did, bob.did)
  const innerJwe = packAuthcrypt(utf8(JSON.stringify(inner)), { kid: alice.xKid, privateKey: alice.xPriv }, [{ kid: bob.xKid, publicKey: bobXPub }])
  const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.xKid })
  forward.attachments = [{ id: 'inner', data: { json: innerJwe } }]
  const forwardJwe = packAnoncrypt(utf8(JSON.stringify(forward)), [{ kid: mediatorXKid, publicKey: mediatorXPub }])
  const res = await fetchImpl(`${mediatorUrl}/`, didCommPost(forwardJwe))
  expect(res.status).toBe(202)
}

describe('mediator client library (mediator-{transport,coordinate,pickup,sync}.ts)', () => {
  test('registerWithMediator + manual pickup + ack: full round trip', async () => {
    const { mediatorIdentity, fetchImpl, url } = freshMediatorFetch()
    const alicePeer = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }

    const info = await registerWithMediator(url, bob, fetchImpl)
    expect(info.did).toBe(mediatorIdentity.did)

    const keys = await queryKeylist(info, bob, fetchImpl)
    expect(keys).toEqual([expect.objectContaining({ device: bob.device })])

    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alicePeer, bob, bobPeer.xPub, 'hello bob')

    expect(await pickupStatus(info, bob, fetchImpl)).toMatchObject({ messageCount: 1 })

    const delivered = await pickupDeliver(info, bob, async () => alicePeer.xPub, 10, fetchImpl)
    expect(delivered).toHaveLength(1)
    expect(delivered[0]!.senderKid).toBe(alicePeer.xKid)
    expect((delivered[0]!.plaintext as any).body.content).toBe('hello bob')

    const remaining = await acknowledgeMessages(info, bob, [delivered[0]!.ackId], fetchImpl)
    expect(remaining).toMatchObject({ messageCount: 0, missed: false })
    expect(await pickupStatus(info, bob, fetchImpl)).toMatchObject({ messageCount: 0 })
  })

  test('two devices of one DID each collect the same Forward through their own inbox', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const alice = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const phone: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-phone-01' }
    const laptop: MediatorInboxClient = { ...phone, device: 'bob-laptop-01' }
    const info = await registerWithMediator(url, phone, fetchImpl)
    await registerWithMediator(url, laptop, fetchImpl)
    expect((await queryKeylist(info, phone, fetchImpl)).map(entry => entry.device)).toEqual(['bob-phone-01', 'bob-laptop-01'])

    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alice, phone, bobPeer.xPub, 'to every device')
    for (const device of [phone, laptop]) {
      const delivered = await pickupDeliver(info, device, async () => alice.xPub, 10, fetchImpl)
      expect((delivered[0]!.plaintext as any).body.content).toBe('to every device')
      expect(await acknowledgeMessages(info, device, [delivered[0]!.ackId], fetchImpl)).toMatchObject({ messageCount: 0 })
    }
  })

  test('re-registering (self-heal) is idempotent and does not disturb the keylist', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const info1 = await registerWithMediator(url, bob, fetchImpl)
    const info2 = await registerWithMediator(url, bob, fetchImpl)
    expect(info2.did).toBe(info1.did)
    const keys = await queryKeylist(info1, bob, fetchImpl)
    expect(keys).toEqual([expect.objectContaining({ device: bob.device })])
  })

  test('requestMediation alone grants without opening an inbox', async () => {
    const { mediatorIdentity, fetchImpl, url } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const info = await fetchMediatorInfo(url, fetchImpl)
    const grant = await requestMediation(info, bob, fetchImpl)
    expect(grant.routingDid).toBe(mediatorIdentity.did)
    expect(await queryKeylist(info, bob, fetchImpl)).toEqual([])
  })

  test('startMediatorPolling delivers a queued message to onMessage and acks it, then stops cleanly', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const alicePeer = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const info = await registerWithMediator(url, bob, fetchImpl)
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alicePeer, bob, bobPeer.xPub, 'polled message')

    const received: string[] = []
    const handle = startMediatorPolling(url, bob, async () => alicePeer.xPub, msg => {
      received.push((msg.plaintext as any).body.content)
    }, { fetch: fetchImpl, intervalMs: 20 })

    const deadline = Date.now() + 2000
    while (received.length === 0 && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 20))
    }
    handle.stop()

    expect(received).toEqual(['polled message'])
    // Acknowledged by the poll loop itself -- nothing left queued.
    expect(await pickupStatus(info, bob, fetchImpl)).toMatchObject({ messageCount: 0 })
  })
})

describe('Pickup 3.0 live mode over WebSocket (server.ts live, mediator-live.ts)', () => {
  test('live-delivery-change pushes a newly queued copy as a delivery, which stays queued until acked', async () => {
    const { fetchImpl, url, live } = freshMediatorFetch()
    const alice = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const info = await registerWithMediator(url, bob, fetchImpl)
    const raw = rawLiveSocket(live)
    await raw.send(packMediatorRequest(info, bob, LIVE_DELIVERY_CHANGE, { recipient_did: bob.did, device: bob.device, live_delivery: true }))
    const enabled = await unpackMediatorMessage(info, bob, JSON.parse(raw.frames[0]!))
    expect(enabled.type).toBe(STATUS)
    expect(enabled.body).toMatchObject({ live_delivery: true, message_count: 0 })

    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alice, bob, bobPeer.xPub, 'pushed live')
    expect(raw.frames).toHaveLength(2)
    const pushed = await unpackMediatorMessage(info, bob, JSON.parse(raw.frames[1]!))
    expect(pushed.type).toBe(DELIVERY)
    expect(pushed.body).toMatchObject({ recipient_did: bob.did, device: bob.device })
    expect(pushed.attachments).toHaveLength(1)
    expect(await pickupStatus(info, bob, fetchImpl)).toMatchObject({ messageCount: 1 })

    // Closing the socket ends live mode: the next copy is only queued.
    live.close(raw.socket)
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alice, bob, bobPeer.xPub, 'after close')
    expect(raw.frames).toHaveLength(2)
  })

  test('live mode is refused over HTTP, and on a socket without return_route', async () => {
    const { fetchImpl, url, live, mediatorIdentity } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const info = await registerWithMediator(url, bob, fetchImpl)
    await expect(sendAndUnpackLive(info, bob, fetchImpl)).rejects.toThrow(LIVE_MODE_NOT_SUPPORTED_PROBLEM)

    // Without return_route the mediator may not answer on the socket at all.
    const raw = rawLiveSocket(live)
    const plaintext = buildPlaintext(LIVE_DELIVERY_CHANGE, { recipient_did: bob.did, device: bob.device, live_delivery: true }, bob.did, mediatorIdentity.did)
    await raw.send(packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: bob.xKid, privateKey: bob.xPriv }, [{ kid: info.xKid, publicKey: info.xPub }]))
    expect(raw.frames).toHaveLength(0)
  })

  test('an HTTP request without return_route is accepted with no reply body', async () => {
    const { fetchImpl, url, mediatorIdentity } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const info = await registerWithMediator(url, bob, fetchImpl)
    const plaintext = buildPlaintext('https://didcomm.org/messagepickup/3.0/status-request', { recipient_did: bob.did, device: bob.device }, bob.did, mediatorIdentity.did)
    const res = await fetchImpl(`${url}/`, didCommPost(packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: bob.xKid, privateKey: bob.xPriv }, [{ kid: info.xKid, publicKey: info.xPub }])))
    expect(res.status).toBe(202)
    expect(await res.text()).toBe('')
  })

  test('watchMediatorLive pulls the backlog with delivery-request, receives live pushes, and acks both', async () => {
    const { fetchImpl, url, webSocketCtor } = freshMediatorFetch()
    const alice = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const info = await registerWithMediator(url, bob, fetchImpl)
    // More than one delivery-request batch, queued before connecting.
    for (let n = 0; n < 12; n++) await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alice, bob, bobPeer.xPub, `backlog ${n}`)

    const received: string[] = []
    const watch = watchMediatorLive({
      mediatorUrl: url, inbox: bob, resolveSenderKey: async () => alice.xPub,
      onMessage: msg => { received.push((msg.plaintext as { body: { content: string } }).body.content) },
      fetch: fetchImpl, webSocketCtor,
    })
    await until(() => received.length === 12)
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alice, bob, bobPeer.xPub, 'live')
    await until(() => received.length === 13)
    await until(() => false, 50)
    watch.close()

    expect(received).toEqual([...Array.from({ length: 12 }, (_, n) => `backlog ${n}`), 'live'])
    expect(await pickupStatus(info, bob, fetchImpl)).toMatchObject({ messageCount: 0 })
  })

  test('one socket carries several inboxes, each enabled by its own authcrypt request', async () => {
    const { fetchImpl, url, webSocketCtor } = freshMediatorFetch()
    const alice = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const carolPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const carol: MediatorInboxClient = { did: carolPeer.did, xKid: carolPeer.xKid, xPriv: carolPeer.xPriv, device: 'carol-device' }
    const info = await registerWithMediator(url, bob, fetchImpl)
    let sockets = 0
    const counting = class extends (webSocketCtor as unknown as new (url: string) => object) { constructor(u: string) { super(u); sockets++ } } as unknown as typeof WebSocket
    const received: string[] = []
    const watches = [bob, carol].map(inbox => watchMediatorLive({
      mediatorUrl: url, inbox, resolveSenderKey: async () => alice.xPub,
      onMessage: msg => { received.push(`${inbox.device}:${(msg.plaintext as { body: { content: string } }).body.content}`) },
      fetch: fetchImpl, webSocketCtor: counting,
    }))
    await until(() => false, 50)
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alice, bob, bobPeer.xPub, 'for bob')
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alice, carol, carolPeer.xPub, 'for carol')
    await until(() => received.length === 2)
    for (const watch of watches) watch.close()
    expect(sockets).toBe(1)
    expect(new Set(received)).toEqual(new Set(['bob-device:for bob', 'carol-device:for carol']))
  })

  test('a status saying the inbox missed copies calls onMissed', async () => {
    const { fetchImpl, url, webSocketCtor, store } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob = (device: string): MediatorInboxClient => ({ did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device })
    await registerWithMediator(url, bob('bob-device-a'), fetchImpl)
    await registerWithMediator(url, bob('bob-device-b'), fetchImpl)
    // Fifteen days on, only bob-b has been seen: bob-a is dormant and the
    // copy queued now skips it.
    const later = Date.now() + 15 * 24 * 60 * 60 * 1000
    store.touch(bobPeer.did, 'bob-device-b', later)
    store.enqueue(bobPeer.did, JSON.stringify({ opaque: true }), later)
    let missed = 0
    const watch = watchMediatorLive({
      mediatorUrl: url, inbox: bob('bob-device-a'), resolveSenderKey: async () => bobPeer.xPub,
      onMessage: () => {}, onMissed: () => { missed++ },
      fetch: fetchImpl, webSocketCtor,
    })
    await until(() => missed > 0)
    watch.close()
    expect(missed).toBe(1)
  })

  test('a failing onMessage leaves the copy queued (no ack) and does not spin', async () => {
    const { fetchImpl, url, webSocketCtor } = freshMediatorFetch()
    const alice = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
    const info = await registerWithMediator(url, bob, fetchImpl)
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alice, bob, bobPeer.xPub, 'fails')
    let attempts = 0
    const watch = watchMediatorLive({
      mediatorUrl: url, inbox: bob, resolveSenderKey: async () => alice.xPub,
      onMessage: () => { attempts++; throw new Error('not now') },
      fetch: fetchImpl, webSocketCtor,
    })
    await until(() => false, 100)
    watch.close()
    expect(attempts).toBe(1)
    expect(await pickupStatus(info, bob, fetchImpl)).toMatchObject({ messageCount: 1 })
  })

  test('over a real Bun server: the WebSocket upgrade on / carries live delivery', async () => {
    const deployment = createMediatorDeployment({ publicUrl: 'http://127.0.0.1', databasePath: ':memory:', port: 0, log: () => {} })
    const url = `http://127.0.0.1:${deployment.server.port}`
    try {
      const alice = generatePeerIdentity()
      const bobPeer = generatePeerIdentity()
      const bob: MediatorInboxClient = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device: 'bob-device' }
      const info = await registerWithMediator(url, bob)
      await forwardFromAliceToBob(fetch, url, info.xKid, info.xPub, alice, bob, bobPeer.xPub, 'queued')
      const received: string[] = []
      const watch = watchMediatorLive({
        mediatorUrl: url, inbox: bob, resolveSenderKey: async () => alice.xPub,
        onMessage: msg => { received.push((msg.plaintext as { body: { content: string } }).body.content) },
      })
      await until(() => received.length === 1)
      await forwardFromAliceToBob(fetch, url, info.xKid, info.xPub, alice, bob, bobPeer.xPub, 'live')
      await until(() => received.length === 2)
      await until(() => false, 50)
      watch.close()
      expect(received).toEqual(['queued', 'live'])
      expect(await pickupStatus(info, bob)).toMatchObject({ messageCount: 0 })
    } finally {
      await deployment.shutdown('test')
    }
  })
})

/** live-delivery-change over plain HTTP -- refused with a problem-report. */
async function sendAndUnpackLive(info: Awaited<ReturnType<typeof fetchMediatorInfo>>, inbox: MediatorInboxClient, fetchImpl: typeof fetch): Promise<DidCommPlaintext> {
  const { sendAndUnpack } = await import('../src/protocol/didcomm/mediator-transport.ts')
  return sendAndUnpack(info, inbox, LIVE_DELIVERY_CHANGE, { recipient_did: inbox.did, device: inbox.device, live_delivery: true }, fetchImpl)
}

describe('mediator transport rules', () => {
  test('a POST without the DIDComm encrypted media type is refused with 415', async () => {
    const { fetchImpl, url, mediatorIdentity } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const plaintext = buildPlaintext(PING, {}, bobPeer.did, mediatorIdentity.did, { returnRoute: 'all' })
    const jwe = packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: bobPeer.xKid, privateKey: bobPeer.xPriv }, [{ kid: mediatorIdentity.xKid, publicKey: mediatorIdentity.xPub }])
    const res = await fetchImpl(`${url}/`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(jwe) })
    expect(res.status).toBe(415)
  })

  test('the mediator answers a Trust Ping with a ping-response, and nothing when none is requested', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }
    const info = await fetchMediatorInfo(url, fetchImpl)
    const { sendAndUnpack } = await import('../src/protocol/didcomm/mediator-transport.ts')
    const reply = await sendAndUnpack(info, bob, PING, {}, fetchImpl)
    expect(reply.type).toBe(PING_RESPONSE)
    const quiet = await fetchImpl(`${url}/`, didCommPost(packMediatorRequest(info, bob, PING, { response_requested: false })))
    expect(quiet.status).toBe(202)
  })
})

describe('device limit', () => {
  test('registerWithMediator turns e.p.req.max-devices into a user-facing error listing the devices', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob = (device: string): MediatorInboxClient => ({ did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv, device })
    for (const device of ['bob-device-1', 'bob-device-2', 'bob-device-3']) await registerWithMediator(url, bob(device), fetchImpl)
    const refused = await registerWithMediator(url, bob('bob-device-4'), fetchImpl).catch(error => error)
    expect(refused).toBeInstanceOf(MediatorDeviceLimitError)
    expect(refused.devices).toHaveLength(3)
    expect(refused.message).toContain('already has 3 devices registered')
    expect(refused.message).toContain('this removes all other devices')
  })
})
