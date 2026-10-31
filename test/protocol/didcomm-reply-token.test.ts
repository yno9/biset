// A mail bridge's reply tokens (didmail PROTOCOL.md §7.1): kept with the contact they are for, sent with every message to it,
// and what the bridge answers an introduction with.
import { describe, expect, test } from 'vitest'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { packAuthcrypt } from '../../src/protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../../src/protocol/didcomm/message.ts'
import { replyTokensOf } from '../../src/protocol/didcomm/reply-token.ts'
import { BASIC_MESSAGE, basicMessageBodyOf } from '../../src/client/didcomm/basicmessage.ts'
import { DidCommIngressProjector } from '../../src/client/didcomm/ingress-projector.ts'
import { sendDidCommMessage } from '../../src/client/didcomm/send-message.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'
import type { VaultEventAuthor } from '../../src/client/store/vault/events.ts'
import { applyContactSet, assertContactCard, contactCardSet, contactCardForDid, didContactPatch, replyTokenOf, replyTokenPatch, REPLY_TOKEN_CONTACT_PROPERTY, type LocalJmapContactCard } from '../../src/client/store/projection/contacts.ts'
import { buildDidCommLog } from './support/did-log-fixture.ts'

const TOKEN = 'AB1_-cdEFghIJklMNopQRst' // an epoch byte and 16 bytes, as 23 characters of base64url
const OTHER_TOKEN = 'ZZ9_-cdEFghIJklMNopQRst'
const aliceDid = 'did:web:did.md:example.com:alice'
const supportDid = 'did:web:did.md:example.com:support'

describe('reading reply tokens', () => {
  test('keeps the well formed entries, at most four, and nothing else', () => {
    expect(replyTokensOf({ [aliceDid]: TOKEN })).toEqual({ [aliceDid]: TOKEN })
    expect(replyTokensOf({ [aliceDid]: TOKEN, 'not a did': TOKEN, [supportDid]: 'short', 'did:web:x:y:z': 5 })).toEqual({ [aliceDid]: TOKEN })
    expect(replyTokensOf({ a: TOKEN })).toBeUndefined()
    for (const bad of [null, 'x', [], 7, {}]) expect(replyTokensOf(bad)).toBeUndefined()
    const many = Object.fromEntries(Array.from({ length: 9 }, (_, n) => [`did:web:did.md:example.com:u${n}`, TOKEN]))
    expect(Object.keys(replyTokensOf(many)!)).toHaveLength(4)
  })

  test('a message body carries them as the bridge put them', () => {
    expect(basicMessageBodyOf({ body: { content: 'x', replyTokens: { [aliceDid]: TOKEN } } })!.replyTokens).toEqual({ [aliceDid]: TOKEN })
    expect('replyTokens' in basicMessageBodyOf({ body: { content: 'x', replyTokens: 'nope' } })!).toBe(false)
  })
})

describe('the token on a contact card', () => {
  test('is written leaf by leaf, replaced by a newer one, and read back', () => {
    let card = applyContactSet(undefined, didContactPatch(aliceDid))!
    expect(replyTokenOf(card)).toBeUndefined()
    card = applyContactSet(card, replyTokenPatch(card.id, TOKEN))!
    expect(replyTokenOf(card)).toBe(TOKEN)
    card = applyContactSet(card, replyTokenPatch(card.id, OTHER_TOKEN))!
    expect(replyTokenOf(card)).toBe(OTHER_TOKEN)
    expect(assertContactCard(card)[REPLY_TOKEN_CONTACT_PROPERTY]).toBe(OTHER_TOKEN)
  })

  test('only something that looks like a token is kept; an app (JMAP) cannot set it', () => {
    expect(() => replyTokenPatch('c1', 'x')).toThrow('not a reply token')
    expect(() => assertContactCard({ ...applyContactSet(undefined, didContactPatch(aliceDid))!, [REPLY_TOKEN_CONTACT_PROPERTY]: 'x y' })).toThrow('reply token')
    const card = applyContactSet(undefined, didContactPatch(aliceDid))!
    const set = contactCardSet({ update: { [card.id]: { [REPLY_TOKEN_CONTACT_PROPERTY]: TOKEN } } }, [card])
    expect(Object.keys(set.notUpdated)).toEqual([card.id])
    expect(set.intents).toEqual([])
  })
})

// ---- the ingress: which tokens are written, and to whose card ----

const identityId = 'did:vh:abc123'
const recipientKid = `${identityId}#k_devicehash`
const senderKid = `${aliceDid}#key-1`
const dmarc = { dmarc: 'pass', domain: 'example.com' }
const signer: VaultEventAuthor = {
  deviceId: recipientKid,
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === recipientKid && equalBytes(signature, await this.sign(bytes)) },
}
const senderX = x25519.utils.randomSecretKey()
const recipientX = x25519.utils.randomSecretKey()
const segmentKey = createSegmentKey()

function projector(cards: LocalJmapContactCard[] = []) {
  const seen = new Set<string>()
  let seq = 0
  return new DidCommIngressProjector({
    identityId, actorDeviceId: recipientKid,
    resolveOwnKey: kid => kid === recipientKid ? { kid: recipientKid, x25519PrivateKey: recipientX } : null,
    async resolveSenderKey() { return x25519.getPublicKey(senderX) },
    async alreadyProcessed(id) { if (seen.has(id)) return true; seen.add(id); return false },
    async nextActorSeq() { return ++seq },
    async initialParents() { return [] },
    async activeSegment() { return { segmentId: 'segment-1', segmentKey } },
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: cards } },
    signer, now: () => new Date('2026-10-20T00:01:00.000Z'),
  })
}

function envelope(body: Record<string, unknown>, from = aliceDid) {
  const plaintext = buildPlaintext(BASIC_MESSAGE, body, from, identityId, {})
  const payload = new TextEncoder().encode(JSON.stringify(packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: `${from}#key-1`, privateKey: senderX }, [{ kid: recipientKid, publicKey: x25519.getPublicKey(recipientX) }])))
  return {
    version: 1, ingressId: crypto.randomUUID(), protocol: 'didcomm', recipientIdentityId: identityId, recipientDeviceSnapshot: [recipientKid],
    createdAt: '2026-10-20T00:00:00.000Z', expiresAt: '2026-10-21T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([1]),
    protectedPayload: payload, protectedPayloadHash: sha256Bytes(payload),
  } satisfies IngressEnvelopeV1
}

describe('a bridged mail with reply tokens', () => {
  test('the token for the sender is kept on the sender\'s card', async () => {
    const { projection } = await projector().verifyAndProject(envelope({ content: 'hi', auth: dmarc, replyTokens: { [aliceDid]: TOKEN } }))
    expect(replyTokenOf(contactCardForDid(projection.contactCards, aliceDid))).toBe(TOKEN)
  })

  test('the token for the Reply-To address is kept on its own card, made for it', async () => {
    const { projection } = await projector().verifyAndProject(envelope({ content: 'hi', auth: dmarc, replyTo: supportDid, replyTokens: { [aliceDid]: TOKEN, [supportDid]: OTHER_TOKEN } }))
    expect(replyTokenOf(contactCardForDid(projection.contactCards, aliceDid))).toBe(TOKEN)
    expect(replyTokenOf(contactCardForDid(projection.contactCards, supportDid))).toBe(OTHER_TOKEN)
  })

  test('not without a DMARC pass, and not for any DID but the sender and its Reply-To', async () => {
    const victim = 'did:web:did.md:example.com:victim'
    for (const body of [
      { content: 'hi', replyTokens: { [aliceDid]: TOKEN } },
      { content: 'hi', auth: { dmarc: 'fail' }, replyTokens: { [aliceDid]: TOKEN } },
    ]) {
      const { projection } = await projector().verifyAndProject(envelope(body))
      expect(replyTokenOf(contactCardForDid(projection.contactCards, aliceDid))).toBeUndefined()
    }
    const { projection } = await projector().verifyAndProject(envelope({ content: 'hi', auth: dmarc, replyTokens: { [aliceDid]: TOKEN, [victim]: OTHER_TOKEN } }))
    expect(contactCardForDid(projection.contactCards, victim)).toBeUndefined()
  })

  test('a DID that is not a mail bridge\'s cannot write tokens', async () => {
    const stranger = 'did:vh:QmNWGCeHpyMMTjFsYmoYaQa6fqGnyYGy45vo9JW9ai5RWF'
    const { projection } = await projector().verifyAndProject(envelope({ content: 'hi', auth: dmarc, replyTokens: { [stranger]: TOKEN } }, stranger))
    expect(replyTokenOf(contactCardForDid(projection.contactCards, stranger))).toBeUndefined()
  })
})

// ---- sending ----

describe('sending with a token', () => {
  const senderKidOwn = 'did:vh:Qmsender#k_senderhash'
  const ownX = x25519.utils.randomSecretKey()
  const recipientXOwn = x25519.utils.randomSecretKey()

  function bridgeRecipient(answer: () => Response) {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const { did, log } = buildDidCommLog({
      rootPrivateKey, rootPublicKey: ed25519.getPublicKey(rootPrivateKey),
      keyAgreementKeys: [{ fragment: 'k_recipienthash', x25519PublicKey: x25519.getPublicKey(recipientXOwn) }], endpointUri: 'https://bridge.example.test/v1/mail', routingKeys: [],
    })
    const posted: string[] = []
    const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/did.jsonl')) return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n', { status: 200 })
      if (url === 'https://bridge.example.test/v1/mail') { posted.push(String(init?.body)); return answer() }
      return new Response('unexpected request: ' + url, { status: 500 })
    }) as typeof fetch
    return { did, fetchImpl, posted }
  }

  async function withFetch<T>(fetchImpl: typeof fetch, run: () => Promise<T>): Promise<T> {
    const real = globalThis.fetch
    globalThis.fetch = fetchImpl
    try { return await run() } finally { globalThis.fetch = real }
  }

  test('the message carries the token in body.replyToken, and has none without one', async () => {
    const { unpackAuthcrypt, parseJwe } = await import('../../src/protocol/didcomm/crypto.ts')
    const to = bridgeRecipient(() => new Response(null, { status: 202 }))
    await withFetch(to.fetchImpl, async () => {
      await sendDidCommMessage(to.did, 'hello', { fromKid: senderKidOwn, x25519PrivateKey: ownX, fetch: to.fetchImpl, replyToken: TOKEN })
      await sendDidCommMessage(to.did, 'again', { fromKid: senderKidOwn, x25519PrivateKey: ownX, fetch: to.fetchImpl })
    })
    const bodies = await Promise.all(to.posted.map(async posted => {
      const { plaintext } = await unpackAuthcrypt(parseJwe(JSON.parse(posted))!, { kid: `${to.did}#k_recipienthash`, privateKey: recipientXOwn }, async () => x25519.getPublicKey(ownX))
      return JSON.parse(new TextDecoder().decode(plaintext)).body as Record<string, unknown>
    }))
    expect(bodies[0]).toMatchObject({ content: 'hello', replyToken: TOKEN })
    expect('replyToken' in bodies[1]!).toBe(false)
  })

  test('what the bridge answers an introduction with is handed back; any other 202 has nothing', async () => {
    const withTokens = bridgeRecipient(() => new Response(JSON.stringify({ replyTokens: { [aliceDid]: TOKEN, junk: 'x' } }), { status: 202, headers: { 'content-type': 'application/json' } }))
    const plain = bridgeRecipient(() => new Response(null, { status: 202 }))
    const garbled = bridgeRecipient(() => new Response('not json', { status: 202, headers: { 'content-type': 'application/json' } }))
    const options = (fetchImpl: typeof fetch) => ({ fromKid: senderKidOwn, x25519PrivateKey: ownX, fetch: fetchImpl })
    expect(await withFetch(withTokens.fetchImpl, () => sendDidCommMessage(withTokens.did, '', options(withTokens.fetchImpl)))).toEqual({ ok: true, replyTokens: { [aliceDid]: TOKEN } })
    expect(await withFetch(plain.fetchImpl, () => sendDidCommMessage(plain.did, '', options(plain.fetchImpl)))).toEqual({ ok: true })
    expect(await withFetch(garbled.fetchImpl, () => sendDidCommMessage(garbled.did, '', options(garbled.fetchImpl)))).toEqual({ ok: true })
  })
})
