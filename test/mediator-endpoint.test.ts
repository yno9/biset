// A service endpoint that names its mediator by DID (DIDComm Messaging v2.1,
// "Using a DID as an endpoint"): resolved to where to POST and whom to wrap for.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { expandEndpoint } from '../src/protocol/didcomm/mediator-endpoint.ts'
import { peerHop, wrapForwardHops } from '../src/protocol/didcomm/forward-wrap.ts'
import { encodeX25519Multikey } from '../src/protocol/didcomm/multikey.ts'
import { generatePeerIdentity, identityFromKeys } from '../src/protocol/didcomm/peer.ts'
import { packAuthcrypt, parseJwe, unpackAnoncrypt, unpackAuthcrypt } from '../src/protocol/didcomm/crypto.ts'
import { FORWARD } from '../src/protocol/didcomm/mediator-protocol.ts'
import { sendFrontDoorMessage } from '../src/client/didcomm/front-door-send.ts'
import { sendDidCommMessage } from '../src/client/didcomm/send-message.ts'
import { buildDidCommLog } from './protocol/support/webvh-log-fixture.ts'
import { serializeLog } from '../src/protocol/webvh/log.ts'

const HOST = 'mediator.example'
const MEDIATOR_DID = `did:web:${HOST}`
const URL_ = `https://${HOST}`
const utf8 = (s: string) => new TextEncoder().encode(s)

/** One mediator, as its did:web document publishes it. */
function mediator(options: { alias?: 'same' | 'other-key' | 'other-url' | 'none'; service?: unknown; id?: string } = {}) {
  const xPriv = x25519.utils.randomSecretKey()
  const edPriv = ed25519.utils.randomSecretKey()
  const xPub = x25519.getPublicKey(xPriv)
  const did = options.id ?? MEDIATOR_DID
  const aliasKeys = options.alias === 'other-key' ? [x25519.utils.randomSecretKey(), edPriv] as const : [xPriv, edPriv] as const
  const alias = identityFromKeys(aliasKeys[0], aliasKeys[1], { uri: options.alias === 'other-url' ? 'https://elsewhere.example' : URL_, accept: ['didcomm/v2'] })
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'], id: did,
    ...(options.alias === 'none' ? {} : { alsoKnownAs: [alias.did] }),
    verificationMethod: [{ id: '#key-1', type: 'Multikey', controller: did, publicKeyMultibase: encodeX25519Multikey(xPub) }],
    keyAgreement: ['#key-1'],
    service: options.service ?? [{ id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: URL_, accept: ['didcomm/v2'] } }],
  }
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = new URL(String(input))
    if (url.origin === URL_ && url.pathname === '/.well-known/did.json') return Response.json(doc)
    return new Response('not found', { status: 404 })
  }) as typeof fetch
  return { xPriv, xPub, kid: `${did}#key-1`, alias, doc, fetchImpl }
}

describe('expandEndpoint', () => {
  test('a plain URL with did:peer routing keys is what it always was: the URL, and a hop per key', async () => {
    const hop1 = generatePeerIdentity({ uri: 'https://hop1.example' })
    const hop2 = generatePeerIdentity()
    const expanded = await expandEndpoint({ uri: 'https://hop1.example', routingKeys: [hop1.xKid, hop2.xKid] }, fetch)
    expect(expanded.url).toBe('https://hop1.example')
    expect(expanded.hops.map(hop => hop.kid)).toEqual([hop1.xKid, hop2.xKid])
    expect(expanded.hops[0]!.recipients[0]!.publicKey).toEqual(hop1.xPub)
    expect(expanded.peerKid).toBe(hop1.xKid)
  })

  test('a plain URL with no routing keys is delivered to directly', async () => {
    expect(await expandEndpoint({ uri: 'https://direct.example' }, fetch)).toEqual({ url: 'https://direct.example', hops: [] })
  })

  test('a mediator named by did:web: its document gives the URL, and its key is the first hop', async () => {
    const m = mediator()
    const expanded = await expandEndpoint({ uri: MEDIATOR_DID }, m.fetchImpl)
    expect(expanded.url).toBe(URL_)
    expect(expanded.hops).toHaveLength(1)
    expect(expanded.hops[0]!.kid).toBe(m.kid)
    expect(expanded.hops[0]!.recipients[0]!.publicKey).toEqual(m.xPub)
    expect(expanded.peerKid).toBe(m.alias.xKid) // for a private relationship, which cannot depend on resolving anything
  })

  test("the mediator's key is PREPENDED to the endpoint's own routingKeys", async () => {
    const m = mediator()
    const another = generatePeerIdentity()
    const expanded = await expandEndpoint({ uri: MEDIATOR_DID, routingKeys: [another.xKid] }, m.fetchImpl)
    expect(expanded.hops.map(hop => hop.kid)).toEqual([m.kid, another.xKid])
  })

  test('a did:peer works as the mediator DID too', async () => {
    const m = generatePeerIdentity({ uri: URL_, accept: ['didcomm/v2'] })
    const expanded = await expandEndpoint({ uri: m.did }, fetch)
    expect(expanded.url).toBe(URL_)
    expect(expanded.hops[0]!.kid).toBe(m.xKid)
    expect(expanded.peerKid).toBe(m.xKid)
  })

  test('an alias that is not the same mediator is ignored: another key, or another URL', async () => {
    expect((await expandEndpoint({ uri: MEDIATOR_DID }, mediator({ alias: 'other-key' }).fetchImpl)).peerKid).toBeUndefined()
    expect((await expandEndpoint({ uri: MEDIATOR_DID }, mediator({ alias: 'other-url' }).fetchImpl)).peerKid).toBeUndefined()
    expect((await expandEndpoint({ uri: MEDIATOR_DID }, mediator({ alias: 'none' }).fetchImpl)).peerKid).toBeUndefined()
  })

  test("a mediator that does not resolve, or whose own endpoint is a DID or has routing keys, is refused", async () => {
    await expect(expandEndpoint({ uri: 'did:web:nowhere.example' }, mediator().fetchImpl)).rejects.toThrow('does not resolve')
    const recursive = mediator({ service: [{ id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: 'did:web:other.example' } }] })
    await expect(expandEndpoint({ uri: MEDIATOR_DID }, recursive.fetchImpl)).rejects.toThrow('plain URL')
    const chained = mediator({ service: [{ id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: URL_, routingKeys: [generatePeerIdentity().xKid] } }] })
    await expect(expandEndpoint({ uri: MEDIATOR_DID }, chained.fetchImpl)).rejects.toThrow('routingKeys')
    await expect(expandEndpoint({ uri: 'did:key:z6Mk' }, fetch)).rejects.toThrow('only did:web and did:peer')
  })
})

describe('wrapForwardHops', () => {
  test('wraps for a did:web hop: anoncrypt to its key, naming the recipient next', async () => {
    const m = mediator()
    const inner = packAuthcrypt(utf8('hello'), { kid: 'did:example:alice#k', privateKey: x25519.utils.randomSecretKey() }, [{ kid: 'did:example:bob#k', publicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()) }])
    const outer = wrapForwardHops(inner, 'did:example:bob', [{ kid: m.kid, recipients: [{ kid: m.kid, publicKey: m.xPub }] }])
    expect(outer.recipients.map(r => r.header.kid)).toEqual([m.kid])
    const forward = JSON.parse(new TextDecoder().decode(await unpackAnoncrypt(outer, { kid: m.kid, privateKey: m.xPriv })))
    expect(forward.type).toBe(FORWARD)
    expect(forward.body.next).toBe('did:example:bob')
    expect(parseJwe(forward.attachments[0].data.json)).toEqual(inner)
  })

  test('a chain: each Forward names the next hop, the innermost names the recipient', async () => {
    const first = generatePeerIdentity(); const second = generatePeerIdentity()
    const inner = packAuthcrypt(utf8('x'), { kid: 'did:example:a#k', privateKey: x25519.utils.randomSecretKey() }, [{ kid: 'did:example:b#k', publicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()) }])
    const outer = wrapForwardHops(inner, 'did:example:bob', [peerHop(first.xKid), peerHop(second.xKid)])
    const one = JSON.parse(new TextDecoder().decode(await unpackAnoncrypt(outer, { kid: first.xKid, privateKey: first.xPriv })))
    expect(one.body.next).toBe(second.xKid)
    const two = JSON.parse(new TextDecoder().decode(await unpackAnoncrypt(parseJwe(one.attachments[0].data.json)!, { kid: second.xKid, privateKey: second.xPriv })))
    expect(two.body.next).toBe('did:example:bob')
  })

  test('no hops is an error: a caller with no mediator delivers directly', () => {
    expect(() => wrapForwardHops({} as never, 'did:example:bob', [])).toThrow('at least one hop')
  })
})

describe('sending to a DID whose endpoint names its mediator by DID', () => {
  /** A did:webvh recipient whose `#didcomm` service is `uri: did:web:mediator.example`, no routingKeys. */
  function recipient(m: ReturnType<typeof mediator>) {
    const root = ed25519.utils.randomSecretKey()
    const xPriv = x25519.utils.randomSecretKey()
    const { did, log } = buildDidCommLog({ rootPrivateKey: root, rootPublicKey: ed25519.getPublicKey(root), keyAgreementKeys: [{ fragment: 'k_front', x25519PublicKey: x25519.getPublicKey(xPriv) }], endpointUri: MEDIATOR_DID, domain: 'bob.example' })
    const posted: Array<{ url: string; body: string }> = []
    const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input))
      if (url.hostname === 'bob.example') return new Response(serializeLog(log))
      if (url.origin === URL_ && url.pathname === '/.well-known/did.json') return m.fetchImpl(input)
      if (url.origin === URL_ && init?.method === 'POST') { posted.push({ url: String(input), body: String(init.body) }); return new Response(null, { status: 202 }) }
      return new Response('unexpected', { status: 500 })
    }) as typeof fetch
    return { did, kid: `${did}#k_front`, xPriv, fetchImpl, posted }
  }

  test('the message is Forward-wrapped for the mediator\'s key and POSTed to the mediator\'s URL', async () => {
    const m = mediator()
    const bob = recipient(m)
    const aliceX = x25519.utils.randomSecretKey()
    const sent = await sendFrontDoorMessage(bob.did, 'https://didcomm.org/basicmessage/2.0/message', { content: 'hi' }, { fromKid: 'did:webvh:scid:alice.example#k_a', x25519PrivateKey: aliceX, fetch: bob.fetchImpl })
    expect(sent).toEqual({ ok: true })
    expect(bob.posted).toHaveLength(1)
    expect(bob.posted[0]!.url).toBe(URL_)
    const forward = JSON.parse(new TextDecoder().decode(await unpackAnoncrypt(parseJwe(JSON.parse(bob.posted[0]!.body))!, { kid: m.kid, privateKey: m.xPriv })))
    expect(forward.type).toBe(FORWARD)
    expect(forward.body.next).toBe(bob.did)
  })

  test('a chat message\'s `created_time` header and its `sentAt` extension come from one instant', async () => {
    const m = mediator()
    const bob = recipient(m)
    const aliceX = x25519.utils.randomSecretKey()
    expect(await sendDidCommMessage(bob.did, 'hi', { fromKid: 'did:webvh:scid:alice.example#k_a', x25519PrivateKey: aliceX, fetch: bob.fetchImpl, subject: 'Greeting' })).toEqual({ ok: true })
    const forward = JSON.parse(new TextDecoder().decode(await unpackAnoncrypt(parseJwe(JSON.parse(bob.posted[0]!.body))!, { kid: m.kid, privateKey: m.xPriv })))
    const { plaintext } = await unpackAuthcrypt(forward.attachments[0].data.json, { kid: bob.kid, privateKey: bob.xPriv }, async () => x25519.getPublicKey(aliceX))
    const message = JSON.parse(new TextDecoder().decode(plaintext))
    expect(message.body.content).toBe('hi')
    expect(message.body.subject).toBe('Greeting')
    expect(Number.isInteger(message.created_time)).toBe(true)
    expect(Math.floor(Date.parse(message.body.sentAt) / 1000)).toBe(message.created_time)
  })


})
