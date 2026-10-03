import { describe, expect, test } from 'bun:test'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { answerTrustPing, sendDidCommMessage } from '../../src/client/didcomm/send-message.ts'
import { PING, PING_RESPONSE } from '../../src/protocol/didcomm/trust-ping.ts'
import { buildPlaintext } from '../../src/protocol/didcomm/message.ts'
import { parseJwe, unpackAuthcrypt, unpackAnoncrypt, b64urlToBytes } from '../../src/protocol/didcomm/crypto.ts'
import { BASIC_MESSAGE } from '../../src/client/didcomm/basicmessage.ts'
import { generatePeerIdentity } from '../../src/protocol/didcomm/peer.ts'
import { buildDidCommLog, type DidCommStateExtras } from '../protocol/support/webvh-log-fixture.ts'
import type { LogEntry } from '../../src/protocol/webvh/log.ts'

const senderKid = 'did:webvh:def456:bob.test.example#k_senderhash'
const senderX = x25519.utils.randomSecretKey()
const recipientX = x25519.utils.randomSecretKey()
const recipientXPub = x25519.getPublicKey(recipientX)

/** A recipient identity as did.md publishes it since routing.json was
 * retired (2026-09-16): `keyAgreement` references and the `#didcomm` service
 * live IN the signed log, so each fixture shape is its own DID (the SCID
 * covers the whole genesis state). */
function recipientIdentity(extras: DidCommStateExtras = {}): { did: string; log: LogEntry[]; kid: string } {
  const rootPrivateKey = ed25519.utils.randomSecretKey()
  const { did, log } = buildDidCommLog({ rootPrivateKey, rootPublicKey: ed25519.getPublicKey(rootPrivateKey), ...extras })
  return { did, log, kid: `${did}#k_recipienthash` }
}

/** The one-device shape almost every test wants: `#k_recipienthash` in
 * `keyAgreement`, `#didcomm` pointing at `endpointUri` via `routingKeys`. */
function oneDevice(endpointUri: string, routingKeys: string[] = []) {
  return recipientIdentity({ keyAgreementKeys: [{ fragment: 'k_recipienthash', x25519PublicKey: recipientXPub }], endpointUri, routingKeys })
}

// Resolution and delivery take their fetch from different places, so the
// fixture swaps globalThis.fetch for the test's duration AND doubles as the
// injectable `opts.fetch` sendDidCommMessage's own POST takes directly.
function withCombinedFetch<T>(handler: typeof fetch, run: (fetchImpl: typeof fetch) => Promise<T>): Promise<T> {
  const realFetch = globalThis.fetch
  globalThis.fetch = handler
  return run(handler).finally(() => { globalThis.fetch = realFetch })
}

function serveLog(log: LogEntry[]): string {
  return log.map(e => JSON.stringify(e)).join('\n') + '\n'
}

/** Serves `log` as the recipient's did.jsonl and captures the POST to
 * `postUrl` (default: the direct-delivery endpoint these tests publish). */
function testFetch(opts: { log?: LogEntry[]; postUrl?: string; postCapture?: { body?: string; url?: string } }): typeof fetch {
  const postUrl = opts.postUrl ?? 'https://recipient-core.test.example/v1/didcomm/ingress'
  return (async (input, init) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.endsWith('/did.jsonl')) {
      if (opts.log === undefined) return new Response('not found', { status: 404 })
      return new Response(serveLog(opts.log), { status: 200 })
    }
    if (url === postUrl) {
      if (opts.postCapture) { opts.postCapture.url = url; opts.postCapture.body = init?.body as string }
      return new Response(null, { status: 202 })
    }
    return new Response('unexpected request: ' + url, { status: 500 })
  }) as typeof fetch
}

describe('sendDidCommMessage', () => {
  test('fails clearly when the recipient identity does not resolve at all', () => withCombinedFetch(
    (async () => new Response('not found', { status: 404 })) as typeof fetch,
    async (fetchImpl) => {
      const result = await sendDidCommMessage(oneDevice('https://unused.test.example').did, 'hi', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fetchImpl })
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.error).toMatch(/does not resolve/)
    },
  ))

  test('fails clearly when the recipient published no DIDComm service (never enabled DIDComm)', () => {
    const to = recipientIdentity()
    return withCombinedFetch(testFetch({ log: to.log }), async (fetchImpl) => {
      const result = await sendDidCommMessage(to.did, 'hi', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fetchImpl })
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.error).toMatch(/no DIDComm service endpoint/)
    })
  })

  test('fails clearly when the document has a service endpoint but no keyAgreement key', () => {
    const to = recipientIdentity({ endpointUri: 'https://recipient-core.test.example/v1/didcomm/ingress' })
    return withCombinedFetch(testFetch({ log: to.log }), async (fetchImpl) => {
      const result = await sendDidCommMessage(to.did, 'hi', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fetchImpl })
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.error).toMatch(/no keyAgreement key/)
    })
  })

  test('resolves the recipient, packs a real authcrypt basicmessage, and POSTs it to their published endpoint', () => {
    const to = oneDevice('https://recipient-core.test.example/v1/didcomm/ingress')
    const captured: { body?: string; url?: string } = {}
    return withCombinedFetch(testFetch({ log: to.log, postCapture: captured }), async (fetchImpl) => {
      const result = await sendDidCommMessage(to.did, 'hello from a real send', {
        fromKid: senderKid, x25519PrivateKey: senderX, subject: 'test subject', fetch: fetchImpl,
      })
      expect(result.ok).toBe(true)
      expect(captured.url).toBe('https://recipient-core.test.example/v1/didcomm/ingress')

      // The recipient side can actually decrypt what was sent.
      const jwe = parseJwe(JSON.parse(captured.body!))
      expect(jwe).not.toBeNull()
      const { plaintext, senderKid: outSenderKid } = await unpackAuthcrypt(jwe!, { kid: to.kid, privateKey: recipientX }, async (kid) => {
        expect(kid).toBe(senderKid)
        return x25519.getPublicKey(senderX)
      })
      expect(outSenderKid).toBe(senderKid)
      const msg = JSON.parse(new TextDecoder().decode(plaintext))
      expect(msg.type).toBe(BASIC_MESSAGE)
      expect(msg.body.content).toBe('hello from a real send')
      expect(msg.body.subject).toBe('test subject')
    })
  })

  test('uses the newest Biset front-door device instead of an older published key', () => {
    const oldPrivateKey = x25519.utils.randomSecretKey()
    const newestPrivateKey = x25519.utils.randomSecretKey()
    // The suffix-bound `#didcomm-biset-<suffix>` form (config.json's
    // `previousIds`): each service names the one device key it belongs to.
    const to = recipientIdentity({
      keyAgreementKeys: [
        { fragment: 'k_olddevice', x25519PublicKey: x25519.getPublicKey(oldPrivateKey) },
        { fragment: 'k_newestdevice', x25519PublicKey: x25519.getPublicKey(newestPrivateKey) },
      ],
      services: [
        { id: '#didcomm-biset-olddevice', uri: 'https://old-device.test.example' },
        { id: '#didcomm-biset-newestdevice', uri: 'https://new-device.test.example' },
      ],
    })
    const newestKid = `${to.did}#k_newestdevice`
    const captured: { body?: string; url?: string } = {}
    return withCombinedFetch(testFetch({ log: to.log, postUrl: 'https://new-device.test.example', postCapture: captured }), async fi => {
      await expect(sendDidCommMessage(to.did, 'new device please', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fi })).resolves.toEqual({ ok: true })
      expect(captured.url).toBe('https://new-device.test.example')
      const jwe = parseJwe(JSON.parse(captured.body!))
      expect(jwe).not.toBeNull()
      await expect(unpackAuthcrypt(jwe!, { kid: newestKid, privateKey: newestPrivateKey }, async () => x25519.getPublicKey(senderX))).resolves.toMatchObject({ senderKid })
    })
  })

  // ARC.md's 2026-08-27 mediator redesign, Phase 5: a recipient who has
  // registered with a mediator publishes `routingKeys` naming it -- the
  // sender must Forward-wrap (anoncrypt to the mediator's kid, POST to the
  // mediator's URL) instead of authcrypt'ing straight to the recipient's
  // core.
  test('Forward-wraps through a registered mediator instead of delivering directly', () => {
    const mediator = generatePeerIdentity({ uri: 'https://mediator.test.example', accept: ['didcomm/v2'] })
    const to = oneDevice('https://mediator.test.example', [mediator.xKid])
    const captured: { body?: string; url?: string } = {}
    return withCombinedFetch(testFetch({ log: to.log, postUrl: 'https://mediator.test.example', postCapture: captured }), async (fi) => {
      const result = await sendDidCommMessage(to.did, 'via mediator', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fi })
      expect(result.ok).toBe(true)
      expect(captured.url).toBe('https://mediator.test.example')

      const outer = parseJwe(JSON.parse(captured.body!))
      expect(outer).not.toBeNull()
      const forwardPlaintext = await unpackAnoncrypt(outer!, { kid: mediator.xKid, privateKey: mediator.xPriv })
      const forward = JSON.parse(new TextDecoder().decode(forwardPlaintext))
      expect(forward.type).toBe('https://didcomm.org/routing/2.0/forward')
      expect(forward.body.next).toBe(to.did)

      const inner = parseJwe(forward.attachments[0].data.json)
      expect(inner).not.toBeNull()
      const { plaintext, senderKid: outSenderKid } = await unpackAuthcrypt(inner!, { kid: to.kid, privateKey: recipientX }, async () => x25519.getPublicKey(senderX))
      expect(outSenderKid).toBe(senderKid)
      const msg = JSON.parse(new TextDecoder().decode(plaintext))
      expect(msg.body.content).toBe('via mediator')
    })
  })

  // Hop chaining (2026-08-30 discussion): a `routingKeys` array with more
  // than one entry nests one Forward per hop, outermost first -- the
  // sender POSTs only to hop1, which never sees anything but an ordinary
  // Forward addressed to hop2's kid.
  test('nests one Forward per hop when routingKeys names a chain', () => {
    const hop1 = generatePeerIdentity({ uri: 'https://hop1.test.example', accept: ['didcomm/v2'] })
    const hop2 = generatePeerIdentity()
    const to = oneDevice('https://hop1.test.example', [hop1.xKid, hop2.xKid])
    const captured: { body?: string; url?: string } = {}
    return withCombinedFetch(testFetch({ log: to.log, postUrl: 'https://hop1.test.example', postCapture: captured }), async (fi) => {
      const result = await sendDidCommMessage(to.did, 'via two hops', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fi })
      expect(result.ok).toBe(true)
      expect(captured.url).toBe('https://hop1.test.example')

      const outerToHop1 = parseJwe(JSON.parse(captured.body!))
      expect(outerToHop1).not.toBeNull()
      const forwardToHop1Bytes = await unpackAnoncrypt(outerToHop1!, { kid: hop1.xKid, privateKey: hop1.xPriv })
      const forwardToHop1 = JSON.parse(new TextDecoder().decode(forwardToHop1Bytes))
      expect(forwardToHop1.type).toBe('https://didcomm.org/routing/2.0/forward')
      expect(forwardToHop1.body.next).toBe(hop2.xKid)

      const outerToHop2 = parseJwe(forwardToHop1.attachments[0].data.json)
      expect(outerToHop2).not.toBeNull()
      const forwardToHop2Bytes = await unpackAnoncrypt(outerToHop2!, { kid: hop2.xKid, privateKey: hop2.xPriv })
      const forwardToHop2 = JSON.parse(new TextDecoder().decode(forwardToHop2Bytes))
      expect(forwardToHop2.type).toBe('https://didcomm.org/routing/2.0/forward')
      expect(forwardToHop2.body.next).toBe(to.did)

      const inner = parseJwe(forwardToHop2.attachments[0].data.json)
      expect(inner).not.toBeNull()
      const { plaintext } = await unpackAuthcrypt(inner!, { kid: to.kid, privateKey: recipientX }, async () => x25519.getPublicKey(senderX))
      const msg = JSON.parse(new TextDecoder().decode(plaintext))
      expect(msg.body.content).toBe('via two hops')
    })
  })

  // Regression guard for the 2026-09-09 fix: a recipient identified only by
  // a did:peer:2 (no domain of its own to publish a did:webvh log at --
  // e.g. an outside DIDComm agent/bot) used to crash resolution with
  // `parseWebvhDid: not a did:webvh identifier` the instant
  // sendFrontDoorMessage/frontDoorMediatorRoute tried to treat it as a
  // did:webvh. did:peer:2 is self-certifying, so no fetch should happen at
  // all for the recipient side -- only the mediator POST itself.
  test('sends directly to a did:peer:2 recipient with no did:webvh resolution', () => {
    const mediator = generatePeerIdentity({ uri: 'https://mediator.test.example', accept: ['didcomm/v2'] })
    const recipient = generatePeerIdentity({ uri: 'https://mediator.test.example', routingKeys: [mediator.xKid] })
    const captured: { body?: string; url?: string } = {}
    const fetchImpl = (async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://mediator.test.example') { captured.url = url; captured.body = init?.body as string; return new Response(null, { status: 202 }) }
      return new Response('unexpected request: ' + url, { status: 500 })
    }) as typeof fetch
    return withCombinedFetch(fetchImpl, async (fi) => {
      const result = await sendDidCommMessage(recipient.did, 'hello agent', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fi })
      expect(result.ok).toBe(true)
      expect(captured.url).toBe('https://mediator.test.example')

      const outer = parseJwe(JSON.parse(captured.body!))
      expect(outer).not.toBeNull()
      const forwardPlaintext = await unpackAnoncrypt(outer!, { kid: mediator.xKid, privateKey: mediator.xPriv })
      const forward = JSON.parse(new TextDecoder().decode(forwardPlaintext))
      expect(forward.type).toBe('https://didcomm.org/routing/2.0/forward')
      expect(forward.body.next).toBe(recipient.did)

      const inner = parseJwe(forward.attachments[0].data.json)
      expect(inner).not.toBeNull()
      const { plaintext, senderKid: outSenderKid } = await unpackAuthcrypt(inner!, { kid: recipient.xKid, privateKey: recipient.xPriv }, async () => x25519.getPublicKey(senderX))
      expect(outSenderKid).toBe(senderKid)
      const msg = JSON.parse(new TextDecoder().decode(plaintext))
      expect(msg.body.content).toBe('hello agent')
    })
  })

  test('fails clearly when a did:peer:2 recipient has published no DIDComm service', () => {
    const recipient = generatePeerIdentity()
    return withCombinedFetch(
      (async (input) => new Response('unexpected request: ' + String(input), { status: 500 })) as typeof fetch,
      async (fi) => {
        const result = await sendDidCommMessage(recipient.did, 'hi', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fi })
        expect(result.ok).toBe(false)
        if (!result.ok) expect(result.error).toMatch(/no DIDComm service endpoint/)
      },
    )
  })
})

describe('answerTrustPing (Trust Ping 2.0)', () => {
  const noRelationship = { contactKeyForOwnKid: async () => null, frontDoor: { fromKid: senderKid, x25519PrivateKey: senderX } }

  test('answers a ping on the front door with a ping-response threaded to it, sent as application/didcomm-encrypted+json', async () => {
    const pinger = oneDevice('https://recipient-core.test.example/v1/didcomm/ingress')
    const ping = buildPlaintext(PING, {}, pinger.did, 'did:webvh:def456:bob.test.example')
    let contentType: string | null = null
    let body: string | undefined
    const handler = testFetch({ log: pinger.log })
    const capturing = (async (input, init) => {
      if (String(input).endsWith('/ingress')) { contentType = new Headers(init?.headers).get('content-type'); body = init?.body as string }
      return handler(input, init)
    }) as typeof fetch
    await withCombinedFetch(capturing, async fetchImpl => {
      const result = await answerTrustPing(ping, senderKid, { ...noRelationship, fetch: fetchImpl })
      expect(result).toEqual({ ok: true })
    })
    expect(contentType).toBe('application/didcomm-encrypted+json')
    const { plaintext } = await unpackAuthcrypt(parseJwe(JSON.parse(body!))!, { kid: pinger.kid, privateKey: recipientX }, async () => x25519.getPublicKey(senderX))
    const response = JSON.parse(new TextDecoder().decode(plaintext))
    expect(response.type).toBe(PING_RESPONSE)
    expect(response.thid).toBe(ping.id)
  })

  test('owes nothing for response_requested: false, or for anything but a ping', async () => {
    const pinger = 'did:webvh:abc:alice.test.example'
    expect(await answerTrustPing(buildPlaintext(PING, { response_requested: false }, pinger), senderKid, noRelationship)).toBeNull()
    expect(await answerTrustPing(buildPlaintext(BASIC_MESSAGE, { content: 'hi' }, pinger), senderKid, noRelationship)).toBeNull()
  })
})
