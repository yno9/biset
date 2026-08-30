// Two-hop relay: a sender nests two Forwards (outer -> hop1/"upstream",
// inner -> hop2/"local"), POSTs only to hop1, and the relay poller running
// alongside hop2 (src/mediator/relay-poller.ts) must pick the outer layer
// up from hop1, unwrap it, and re-Forward the still-opaque inner attachment
// into hop2's own queue -- all without either mediator's dispatch() ever
// being told about hop chaining (2026-08-30 discussion).
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { createMediator } from '../../src/mediator/server.ts'
import { startRelayPoller } from '../../src/mediator/relay-poller.ts'
import { registerWithMediator } from '../../src/didcomm/mediator-sync.ts'
import { pickupStatus, pickupDeliver, acknowledgeMessages } from '../../src/didcomm/mediator-pickup.ts'
import type { DidCommSender } from '../../src/didcomm/mediator-transport.ts'
import { packAuthcrypt, packAnoncrypt } from '../../src/didcomm/crypto.ts'
import { buildPlaintext } from '../../src/didcomm/message.ts'
import { FORWARD } from '../../src/didcomm/mediator-protocol.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)

function freshMediator() {
  const url = `https://mediator-${crypto.randomUUID()}.test.example`
  const mediator = generatePeerIdentity({ uri: url, accept: ['didcomm/v2'] })
  const { handle } = createMediator({ mediator })
  return { mediator, handle, url }
}

describe('relay poller (multi-hop Forward chaining)', () => {
  test('re-forwards a message nested for a second hop into the local mediator, unmodified', async () => {
    const upstream = freshMediator() // hop1, what the sender POSTs to directly
    const local = freshMediator() // hop2, running the relay poller

    // Routes both mediators' HTTP surface to their own in-process `handle` --
    // same fake-fetch-by-URL pattern test/mediator-client.test.ts already uses.
    const fetchImpl: typeof fetch = async (input, init) => {
      const reqUrl = new URL(String(input))
      const target = reqUrl.origin === new URL(upstream.url).origin ? upstream : local
      const res = await target.handle(new Request(reqUrl, init), reqUrl)
      return res ?? new Response('not found', { status: 404 })
    }

    // The recipient registers with the LOCAL mediator only -- exactly as if
    // its routing.json named local.mediator as the final hop.
    const recipientPeer = generatePeerIdentity()
    const recipient: DidCommSender = { did: recipientPeer.did, xKid: recipientPeer.xKid, xPriv: recipientPeer.xPriv }
    await registerWithMediator(local.url, recipient, fetchImpl)

    // The poller's own identity is what the sender's routing.json names as
    // the intermediate `routingKeys` entry for hop1 -- persisted in
    // production (SqliteMediatorStore.loadRelayPollerIdentity), a fresh
    // generatePeerIdentity() here. Registered with the upstream mediator up
    // front, same as a routing.json would only ever name a kid the poller
    // already enrolled (a sender has no other way to learn about it).
    const relayIdentity = generatePeerIdentity()
    const relayOwn: DidCommSender = { did: relayIdentity.did, xKid: relayIdentity.xKid, xPriv: relayIdentity.xPriv }
    await registerWithMediator(upstream.url, relayOwn, fetchImpl)

    // Sender builds the nested structure itself (no relay-side code
    // involved in building it) -- innermost payload, then Forward-wrap once
    // per hop, outermost first is what actually gets POSTed.
    const senderPeer = generatePeerIdentity()
    const inner = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'via two hops' }, senderPeer.did, recipientPeer.did)
    const innerJwe = packAuthcrypt(utf8(JSON.stringify(inner)), { kid: senderPeer.xKid, privateKey: senderPeer.xPriv }, { kid: recipientPeer.xKid, publicKey: recipientPeer.xPub })

    const forwardToHop2 = buildPlaintext(FORWARD, { next: recipientPeer.xKid })
    forwardToHop2.attachments = [{ id: 'inner', data: { json: innerJwe } }]
    const forwardToHop2Jwe = packAnoncrypt(utf8(JSON.stringify(forwardToHop2)), { kid: relayIdentity.xKid, publicKey: relayIdentity.xPub })

    const forwardToHop1 = buildPlaintext(FORWARD, { next: relayIdentity.xKid })
    forwardToHop1.attachments = [{ id: 'inner', data: { json: forwardToHop2Jwe } }]
    const forwardToHop1Jwe = packAnoncrypt(utf8(JSON.stringify(forwardToHop1)), { kid: upstream.mediator.xKid, publicKey: upstream.mediator.xPub })

    const postResult = await fetchImpl(upstream.url, { method: 'POST', body: JSON.stringify(forwardToHop1Jwe) })
    expect(postResult.status).toBe(202)

    // Nothing has reached the local mediator's queue yet -- only the relay
    // poller running alongside it can get it there.
    expect(await pickupStatus({ url: local.url, did: local.mediator.did, xKid: local.mediator.xKid, xPub: local.mediator.xPub }, recipient, fetchImpl)).toBe(0)

    const poller = startRelayPoller(
      upstream.url,
      relayOwn,
      local.mediator.xKid,
      async (outbound) => {
        const req = new Request(local.url, { method: 'POST', body: JSON.stringify(outbound) })
        const res = await local.handle(req, new URL(local.url))
        if (!res || res.status !== 202) throw new Error(`unexpected status ${res?.status}`)
      },
      { fetch: fetchImpl, intervalMs: 20 },
    )

    const deadline = Date.now() + 2000
    let delivered: Awaited<ReturnType<typeof pickupDeliver>> = []
    const localInfo = { url: local.url, did: local.mediator.did, xKid: local.mediator.xKid, xPub: local.mediator.xPub }
    while (delivered.length === 0 && Date.now() < deadline) {
      delivered = await pickupDeliver(localInfo, recipient, async () => senderPeer.xPub, 10, fetchImpl)
      if (delivered.length === 0) await new Promise(r => setTimeout(r, 20))
    }
    poller.stop()

    expect(delivered).toHaveLength(1)
    expect((delivered[0]!.plaintext as any).body.content).toBe('via two hops')
    expect(delivered[0]!.senderKid).toBe(senderPeer.xKid)
    await acknowledgeMessages(localInfo, recipient, delivered.map(d => d.ackId), fetchImpl)
    expect(await pickupStatus(localInfo, recipient, fetchImpl)).toBe(0)
  })
})
