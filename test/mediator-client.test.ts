// End-to-end coverage for the CLIENT side of the standalone mediator
// protocol (src/didcomm/mediator-{transport,coordinate,pickup,sync}.ts,
// ARC.md's 2026-08-27 redesign, Phase 4) -- driven against the same
// createMediator handler Phase 3's test exercises directly, but this time
// entirely through the client library a real device would use. The
// mediator's HTTP surface is faked as a fetch that dispatches straight into
// the in-process handler, so this is a real protocol round trip with no
// network.
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../src/shared/didcomm/peer.ts'
import { createMediator } from '../src/server/didcomm-mediator/server.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist, queryKeylist } from '../src/shared/didcomm/mediator-coordinate.ts'
import { pickupStatus, pickupDeliver, acknowledgeMessages } from '../src/shared/didcomm/mediator-pickup.ts'
import { registerWithMediator, startMediatorPolling } from '../src/shared/didcomm/mediator-sync.ts'
import { requestWatch, mediatorStreamUrl } from '../src/shared/didcomm/mediator-pickup.ts'
import { watchMediator } from '../src/shared/didcomm/mediator-watch.ts'
import type { DidCommSender } from '../src/shared/didcomm/mediator-transport.ts'
import { packAuthcrypt, packAnoncrypt } from '../src/shared/didcomm/crypto.ts'
import { buildPlaintext } from '../src/shared/didcomm/message.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)

/** A fresh, unique mediator URL per call -- fetchMediatorInfo caches its
 * result IN-MEMORY per URL (mediator-transport.ts's own note: right for a
 * real deployment's stable URL, but a shared constant across tests would
 * have one test's cached MediatorInfo silently answer for a DIFFERENT
 * freshly-minted mediator identity in the next). */
function freshMediatorFetch() {
  const url = `https://mediator-${crypto.randomUUID()}.test.example`
  const mediator = generatePeerIdentity({ uri: url, accept: ['didcomm/v2'] })
  const { handle } = createMediator({ mediator })
  const fetchImpl: typeof fetch = async (input, init) => {
    const reqUrl = new URL(String(input))
    const res = await handle(new Request(reqUrl, init), reqUrl)
    return res ?? new Response('not found', { status: 404 })
  }
  return { mediatorIdentity: mediator, fetchImpl, url }
}

/** Simulates what Phase 5's send-message.ts will build: alice authcrypts to
 * bob's kid, then anoncrypts a Forward naming it as `next` to the
 * mediator's own kid, and delivers it straight into the mediator (there is
 * no sender-side client library yet -- that is Phase 5). */
async function forwardFromAliceToBob(fetchImpl: typeof fetch, mediatorUrl: string, mediatorXKid: string, mediatorXPub: Uint8Array, alice: ReturnType<typeof generatePeerIdentity>, bob: DidCommSender, bobXPub: Uint8Array, content: string) {
  const inner = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content }, alice.did, bob.did)
  const innerJwe = packAuthcrypt(utf8(JSON.stringify(inner)), { kid: alice.xKid, privateKey: alice.xPriv }, { kid: bob.xKid, publicKey: bobXPub })
  const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.xKid })
  forward.attachments = [{ id: 'inner', data: { json: innerJwe } }]
  const forwardJwe = packAnoncrypt(utf8(JSON.stringify(forward)), { kid: mediatorXKid, publicKey: mediatorXPub })
  const res = await fetchImpl(`${mediatorUrl}/`, { method: 'POST', body: JSON.stringify(forwardJwe) })
  expect(res.status).toBe(202)
}

describe('mediator client library (mediator-{transport,coordinate,pickup,sync}.ts)', () => {
  test('registerWithMediator + manual pickup + ack: full round trip', async () => {
    const { mediatorIdentity, fetchImpl, url } = freshMediatorFetch()
    const alicePeer = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: DidCommSender = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }

    const info = await registerWithMediator(url, bob, fetchImpl)
    expect(info.did).toBe(mediatorIdentity.did)

    const keys = await queryKeylist(info, bob, fetchImpl)
    expect(keys).toEqual([{ kid: bob.xKid }])

    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alicePeer, bob, bobPeer.xPub, 'hello bob')

    expect(await pickupStatus(info, bob, fetchImpl)).toBe(1)

    const delivered = await pickupDeliver(info, bob, async () => alicePeer.xPub, 10, fetchImpl)
    expect(delivered).toHaveLength(1)
    expect(delivered[0]!.senderKid).toBe(alicePeer.xKid)
    expect((delivered[0]!.plaintext as any).body.content).toBe('hello bob')

    const remaining = await acknowledgeMessages(info, bob, [delivered[0]!.ackId], fetchImpl)
    expect(remaining).toBe(0)
    expect(await pickupStatus(info, bob, fetchImpl)).toBe(0)
  })

  test('re-registering (self-heal) is idempotent and does not disturb the keylist', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob: DidCommSender = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }
    const info1 = await registerWithMediator(url, bob, fetchImpl)
    const info2 = await registerWithMediator(url, bob, fetchImpl)
    expect(info2.did).toBe(info1.did)
    const keys = await queryKeylist(info1, bob, fetchImpl)
    expect(keys).toEqual([{ kid: bob.xKid }])
  })

  test('requestMediation alone grants without registering a kid', async () => {
    const { mediatorIdentity, fetchImpl, url } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const bob: DidCommSender = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }
    const info = await fetchMediatorInfo(url, fetchImpl)
    const grant = await requestMediation(info, bob, fetchImpl)
    expect(grant.routingDid).toBe(mediatorIdentity.did)
    expect(await queryKeylist(info, bob, fetchImpl)).toEqual([])
  })

  test('startMediatorPolling delivers a queued message to onMessage and acks it, then stops cleanly', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const alicePeer = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: DidCommSender = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }
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
    expect(await pickupStatus(info, bob, fetchImpl)).toBe(0)
  })
})

/** Reads SSE `data: ...` lines off one stream, accumulating across chunk
 * boundaries (a `ReadableStream` makes no promise that one
 * `controller.enqueue` call in server.ts becomes exactly one `reader.read()`
 * result). Stateful across calls to `next(count)` -- a single reader is
 * acquired once (a `ReadableStream` throws if `getReader()` is called twice
 * on the same body) and reused for every subsequent read on that same
 * connection, exactly like a real `EventSource` staying open across
 * multiple pushes. */
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

describe('mediator live watch (mediator-watch.ts, server.ts GET /stream)', () => {
  test('GET /stream sends the already-queued backlog, then a live push for a message queued after connecting', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const alicePeer = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: DidCommSender = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }
    const info = await registerWithMediator(url, bob, fetchImpl)

    // Queued BEFORE the watch connects -- must arrive as backlog.
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alicePeer, bob, bobPeer.xPub, 'already queued')

    const { token } = await requestWatch(info, bob, fetchImpl)
    const response = await fetchImpl(mediatorStreamUrl(url, token), { method: 'GET' })
    expect(response.headers.get('content-type')).toBe('text/event-stream')
    const frames = sseFrameReader(response)

    const [backlog] = await frames.next(1)
    expect(backlog).toBeDefined()

    // A SECOND message, queued while the connection is already open -- must
    // arrive live, not require a reconnect.
    const readLive = frames.next(1)
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alicePeer, bob, bobPeer.xPub, 'pushed live')
    const [live] = await readLive
    expect(live).toBeDefined()
    expect(live!.id).not.toBe(backlog!.id)
    await frames.close()
  })

  test('an invalid or expired token is refused', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const response = await fetchImpl(mediatorStreamUrl(url, 'not-a-real-token'), { method: 'GET' })
    expect(response.status).toBe(403)
  })

  test('requestWatch for a kid this connection does not own is refused', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const bobPeer = generatePeerIdentity()
    const strangerPeer = generatePeerIdentity()
    await registerWithMediator(url, { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }, fetchImpl)
    const info = await fetchMediatorInfo(url, fetchImpl)
    // strangerPeer never keylist-registered bob's kid -- asking to watch
    // themselves (their OWN unregistered kid) must still be refused, since
    // denyUnlessOwned checks connection ownership, not just "some connection
    // owns this kid".
    await expect(requestWatch(info, { did: strangerPeer.did, xKid: strangerPeer.xKid, xPriv: strangerPeer.xPriv }, fetchImpl)).rejects.toThrow()
  })

  test('watchMediator (FakeEventSource) delivers a queued message and acks it', async () => {
    const { fetchImpl, url } = freshMediatorFetch()
    const alicePeer = generatePeerIdentity()
    const bobPeer = generatePeerIdentity()
    const bob: DidCommSender = { did: bobPeer.did, xKid: bobPeer.xKid, xPriv: bobPeer.xPriv }
    const info = await registerWithMediator(url, bob, fetchImpl)
    await forwardFromAliceToBob(fetchImpl, url, info.xKid, info.xPub, alicePeer, bob, bobPeer.xPub, 'watched message')

    class FakeEventSource {
      onmessage: ((event: { data: string }) => void) | null = null
      onerror: (() => void) | null = null
      private closed = false
      constructor(public readonly streamUrl: string) {
        void this.pump()
      }
      private async pump(): Promise<void> {
        const response = await fetchImpl(this.streamUrl, { method: 'GET' })
        const [frame] = await sseFrameReader(response).next(1)
        if (this.closed || !frame) return
        this.onmessage?.({ data: JSON.stringify(frame) })
      }
      close(): void { this.closed = true }
    }

    const received: string[] = []
    const watch = watchMediator({
      mediatorUrl: url, own: bob, resolveSenderKey: async () => alicePeer.xPub,
      onMessage: msg => { received.push((msg.plaintext as any).body.content) },
      fetch: fetchImpl,
      eventSourceCtor: FakeEventSource as unknown as typeof EventSource,
    })

    const deadline = Date.now() + 2000
    while (received.length === 0 && Date.now() < deadline) await new Promise(r => setTimeout(r, 10))
    watch.close()

    expect(received).toEqual(['watched message'])
    // watchMediator acks after a successful onMessage -- nothing left queued.
    expect(await pickupStatus(info, bob, fetchImpl)).toBe(0)
  })
})
