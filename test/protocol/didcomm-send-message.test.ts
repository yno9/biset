import { describe, expect, test } from 'bun:test'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { sendDidCommMessage } from '../../src/didcomm/send-message.ts'
import { parseJwe, unpackAuthcrypt, unpackAuthcryptHybrid, unpackAnoncrypt, b64urlToBytes } from '../../src/didcomm/crypto.ts'
import { BASIC_MESSAGE } from '../../src/didcomm/basicmessage.ts'
import { encodeX25519Multikey, encodeMlkem768Multikey } from '../../src/didcomm/multikey.ts'
import { mlkemKidFor } from '../../src/didcomm/devicekid.ts'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { buildGenesisLog } from '../protocol/support/webvh-log-fixture.ts'

const rootPrivateKey = ed25519.utils.randomSecretKey()
const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
const { did: recipientDid, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
const recipientX = x25519.utils.randomSecretKey()
const recipientXPub = x25519.getPublicKey(recipientX)
const recipientKid = `${recipientDid}#k_recipienthash`
const senderKid = 'did:webvh:def456:bob.test.example#k_senderhash'
const senderX = x25519.utils.randomSecretKey()

// resolveWithRouting's own resolve() half always uses the real global fetch
// (identity/webvh/resolver.ts has no injection point -- that module's own
// header, a deliberately read-only signing-only subset) -- so the fixture
// has to swap globalThis.fetch for the test's duration AND double as the
// injectable `opts.fetch` sendDidCommMessage's other calls (routing.json,
// the actual DIDComm POST) take directly. Same combined-stub pattern
// test/core/adapters/mail-submission-e2e.test.ts uses for the same reason.
function withCombinedFetch<T>(handler: typeof fetch, run: (fetchImpl: typeof fetch) => Promise<T>): Promise<T> {
  const realFetch = globalThis.fetch
  globalThis.fetch = handler
  return run(handler).finally(() => { globalThis.fetch = realFetch })
}

function testFetch(opts: { routingJson?: unknown; postCapture?: { body?: string; url?: string } }): typeof fetch {
  return (async (input, init) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.endsWith('/did.jsonl')) return new Response(log.map(e => JSON.stringify(e)).join('\n') + '\n', { status: 200 })
    if (url.endsWith('/routing.json')) {
      if (opts.routingJson === undefined) return new Response('not found', { status: 404 })
      return new Response(JSON.stringify(opts.routingJson), { status: 200 })
    }
    if (url === 'https://recipient-core.test.example/v1/didcomm/ingress') {
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
      const result = await sendDidCommMessage(recipientDid, 'hi', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fetchImpl })
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.error).toMatch(/does not resolve/)
    },
  ))

  test('fails clearly when the recipient has no routing.json (never enabled DIDComm)', () => withCombinedFetch(
    testFetch({}),
    async (fetchImpl) => {
      const result = await sendDidCommMessage(recipientDid, 'hi', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fetchImpl })
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.error).toMatch(/no DIDComm service endpoint/)
    },
  ))

  test('fails clearly when routing.json has a service endpoint but no keyAgreement key', () => withCombinedFetch(
    testFetch({ routingJson: { service: [{ id: `${recipientDid}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://recipient-core.test.example/v1/didcomm/ingress', accept: ['didcomm/v2'], routingKeys: [] } }] } }),
    async (fetchImpl) => {
      const result = await sendDidCommMessage(recipientDid, 'hi', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fetchImpl })
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.error).toMatch(/no keyAgreement key/)
    },
  ))

  test('resolves the recipient, packs a real authcrypt basicmessage, and POSTs it to their published endpoint', () => {
    const routingJson = {
      service: [{ id: `${recipientDid}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://recipient-core.test.example/v1/didcomm/ingress', accept: ['didcomm/v2'], routingKeys: [] } }],
      keyAgreementVerificationMethod: [{ id: recipientKid, type: 'Multikey', controller: recipientDid, publicKeyMultibase: encodeX25519Multikey(recipientXPub) }],
    }
    const captured: { body?: string; url?: string } = {}
    return withCombinedFetch(testFetch({ routingJson, postCapture: captured }), async (fetchImpl) => {
      const result = await sendDidCommMessage(recipientDid, 'hello from a real send', {
        fromKid: senderKid, x25519PrivateKey: senderX, subject: 'test subject', fetch: fetchImpl,
      })
      expect(result.ok).toBe(true)
      expect(captured.url).toBe('https://recipient-core.test.example/v1/didcomm/ingress')

      // The recipient side can actually decrypt what was sent.
      const jwe = parseJwe(JSON.parse(captured.body!))
      expect(jwe).not.toBeNull()
      const { plaintext, senderKid: outSenderKid } = await unpackAuthcrypt(jwe!, { kid: recipientKid, privateKey: recipientX }, async (kid) => {
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

  // Root-cause regression guard: sendDidCommMessage must actually reach for
  // packAuthcryptHybrid when the recipient published an ML-KEM-768 entry --
  // that path had zero production callers (test-only) until this fix, so
  // every real message stayed classical-only even when both sides supported
  // post-quantum authcrypt.
  test('upgrades to hybrid X25519+ML-KEM-768 authcrypt when the recipient published an mlkem key', () => {
    const recipientKem = ml_kem768.keygen()
    const routingJson = {
      service: [{ id: `${recipientDid}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://recipient-core.test.example/v1/didcomm/ingress', accept: ['didcomm/v2'], routingKeys: [] } }],
      keyAgreementVerificationMethod: [{ id: recipientKid, type: 'Multikey', controller: recipientDid, publicKeyMultibase: encodeX25519Multikey(recipientXPub) }],
      mlkemVerificationMethod: [{ id: mlkemKidFor(recipientKid), type: 'Multikey', controller: recipientDid, publicKeyMultibase: encodeMlkem768Multikey(recipientKem.publicKey) }],
    }
    const captured: { body?: string; url?: string } = {}
    return withCombinedFetch(testFetch({ routingJson, postCapture: captured }), async (fetchImpl) => {
      const result = await sendDidCommMessage(recipientDid, 'pq please', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fetchImpl })
      expect(result.ok).toBe(true)

      const jwe = parseJwe(JSON.parse(captured.body!))
      expect(jwe).not.toBeNull()
      const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe!.protected)))
      expect(header.alg).toBe('ECDH-1PU-X25519MLKEM768+A256KW')

      const { plaintext, senderKid: outSenderKid } = await unpackAuthcryptHybrid(jwe!, {
        kid: recipientKid, x25519PrivateKey: recipientX, mlkemPrivateKey: recipientKem.secretKey,
      }, async (kid) => {
        expect(kid).toBe(senderKid)
        return x25519.getPublicKey(senderX)
      })
      expect(outSenderKid).toBe(senderKid)
      const msg = JSON.parse(new TextDecoder().decode(plaintext))
      expect(msg.body.content).toBe('pq please')
    })
  })

  // ARC.md's 2026-08-27 mediator redesign, Phase 5: a recipient who has
  // registered with a mediator publishes `routingKeys` naming it -- the
  // sender must Forward-wrap (anoncrypt to the mediator's kid, POST to the
  // mediator's URL) instead of authcrypt'ing straight to the recipient's
  // core.
  test('Forward-wraps through a registered mediator instead of delivering directly', () => {
    const mediator = generatePeerIdentity({ uri: 'https://mediator.test.example', accept: ['didcomm/v2'] })
    const routingJson = {
      service: [{ id: `${recipientDid}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://mediator.test.example', accept: ['didcomm/v2'], routingKeys: [mediator.xKid] } }],
      keyAgreementVerificationMethod: [{ id: recipientKid, type: 'Multikey', controller: recipientDid, publicKeyMultibase: encodeX25519Multikey(recipientXPub) }],
    }
    const captured: { body?: string; url?: string } = {}
    const fetchImpl = (async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.endsWith('/did.jsonl')) return new Response(log.map(e => JSON.stringify(e)).join('\n') + '\n', { status: 200 })
      if (url.endsWith('/routing.json')) return new Response(JSON.stringify(routingJson), { status: 200 })
      if (url === 'https://mediator.test.example') { captured.url = url; captured.body = init?.body as string; return new Response(null, { status: 202 }) }
      return new Response('unexpected request: ' + url, { status: 500 })
    }) as typeof fetch
    return withCombinedFetch(fetchImpl, async (fi) => {
      const result = await sendDidCommMessage(recipientDid, 'via mediator', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fi })
      expect(result.ok).toBe(true)
      expect(captured.url).toBe('https://mediator.test.example')

      const outer = parseJwe(JSON.parse(captured.body!))
      expect(outer).not.toBeNull()
      const forwardPlaintext = await unpackAnoncrypt(outer!, { kid: mediator.xKid, privateKey: mediator.xPriv })
      const forward = JSON.parse(new TextDecoder().decode(forwardPlaintext))
      expect(forward.type).toBe('https://didcomm.org/routing/2.0/forward')
      expect(forward.body.next).toBe(recipientKid)

      const inner = parseJwe(forward.attachments[0].data.json)
      expect(inner).not.toBeNull()
      const { plaintext, senderKid: outSenderKid } = await unpackAuthcrypt(inner!, { kid: recipientKid, privateKey: recipientX }, async () => x25519.getPublicKey(senderX))
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
    const routingJson = {
      service: [{ id: `${recipientDid}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://hop1.test.example', accept: ['didcomm/v2'], routingKeys: [hop1.xKid, hop2.xKid] } }],
      keyAgreementVerificationMethod: [{ id: recipientKid, type: 'Multikey', controller: recipientDid, publicKeyMultibase: encodeX25519Multikey(recipientXPub) }],
    }
    const captured: { body?: string; url?: string } = {}
    const fetchImpl = (async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.endsWith('/did.jsonl')) return new Response(log.map(e => JSON.stringify(e)).join('\n') + '\n', { status: 200 })
      if (url.endsWith('/routing.json')) return new Response(JSON.stringify(routingJson), { status: 200 })
      if (url === 'https://hop1.test.example') { captured.url = url; captured.body = init?.body as string; return new Response(null, { status: 202 }) }
      return new Response('unexpected request: ' + url, { status: 500 })
    }) as typeof fetch
    return withCombinedFetch(fetchImpl, async (fi) => {
      const result = await sendDidCommMessage(recipientDid, 'via two hops', { fromKid: senderKid, x25519PrivateKey: senderX, fetch: fi })
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
      expect(forwardToHop2.body.next).toBe(recipientKid)

      const inner = parseJwe(forwardToHop2.attachments[0].data.json)
      expect(inner).not.toBeNull()
      const { plaintext } = await unpackAuthcrypt(inner!, { kid: recipientKid, privateKey: recipientX }, async () => x25519.getPublicKey(senderX))
      const msg = JSON.parse(new TextDecoder().decode(plaintext))
      expect(msg.body.content).toBe('via two hops')
    })
  })
})
