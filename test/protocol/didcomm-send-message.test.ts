import { describe, expect, test } from 'bun:test'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { sendDidCommMessage } from '../../src/didcomm/send-message.ts'
import { parseJwe, unpackAuthcrypt } from '../../src/didcomm/crypto.ts'
import { BASIC_MESSAGE } from '../../src/didcomm/basicmessage.ts'
import { encodeX25519Multikey } from '../../src/didcomm/multikey.ts'
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
})
