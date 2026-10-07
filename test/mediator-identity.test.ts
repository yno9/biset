// The mediator as a did:web (the DID a recipient's DID document names as its
// endpoint), with the did:peer of the same keys still accepted.
import { describe, expect, test } from 'bun:test'
import { didWebForUrl, peerMediatorIdentity, webMediatorIdentity } from '../src/server/mediator/identity.ts'
import { SqliteMediatorStore } from '../src/server/mediator/sqlite-store.ts'
import { resolveDidWeb } from '../src/protocol/didcomm/did-web.ts'
import { keyAgreementRecipients } from '../src/protocol/didcomm/webvh-route.ts'
import { expandEndpoint } from '../src/protocol/didcomm/mediator-endpoint.ts'
import { fetchMediatorInfo } from '../src/protocol/didcomm/mediator-transport.ts'
import { packAnoncrypt, packAuthcrypt, parseJwe, unpackAuthcrypt } from '../src/protocol/didcomm/crypto.ts'
import { buildPlaintext, type DidCommPlaintext } from '../src/protocol/didcomm/message.ts'
import { decodePeerDid2 } from '../src/protocol/didcomm/peer.ts'
import { freshMediator, freshMediatorFetch, MEDIATOR_URL, peer, T, utf8 } from './support/mediator.ts'

describe('didWebForUrl', () => {
  test('host, port and path become did:web segments', () => {
    expect(didWebForUrl('https://mediator.example')).toBe('did:web:mediator.example')
    expect(didWebForUrl('https://mediator.example/')).toBe('did:web:mediator.example')
    expect(didWebForUrl('https://mediator.example:8443')).toBe('did:web:mediator.example%3A8443')
    expect(didWebForUrl('https://example.org/didcomm/mediator')).toBe('did:web:example.org:didcomm:mediator')
  })
  test('refuses anything but https', () => {
    expect(() => didWebForUrl('http://mediator.example')).toThrow('https')
  })
})

describe('the mediator\'s did:web document', () => {
  test('lists its keys, its URL and the did:peer of the same keys', async () => {
    const { handle, mediator } = freshMediator()
    const url = new URL('/.well-known/did.json', MEDIATOR_URL)
    const doc = await (await handle(new Request(url), url))!.json() as Record<string, any>
    expect(doc.id).toBe('did:web:mediator.test.example')
    expect(mediator.did).toBe(doc.id)
    expect(doc.keyAgreement).toEqual(['#key-1'])
    expect(doc.authentication).toEqual(['#key-2'])
    expect(doc.service[0].type).toBe('DIDCommMessaging')
    expect(doc.service[0].serviceEndpoint.uri).toBe(MEDIATOR_URL)
    expect(doc.alsoKnownAs).toEqual([mediator.aliasKids[0]!.split('#')[0]])
    expect(doc.alsoKnownAs[0]).toMatch(/^did:peer:2\./)
  })

  test('a client can learn the mediator from it: by URL, by did:web resolution, and as an endpoint', async () => {
    const { fetchImpl, mediatorIdentity, url } = freshMediatorFetch()
    const info = await fetchMediatorInfo(url, fetchImpl)
    expect(info).toMatchObject({ url, did: mediatorIdentity.did, xKid: mediatorIdentity.xKid })
    expect(info.xPub).toEqual(mediatorIdentity.xPub)

    const resolved = await resolveDidWeb(mediatorIdentity.did, fetchImpl)
    expect(keyAgreementRecipients(resolved!).map(key => key.kid)).toEqual([mediatorIdentity.xKid])

    const expanded = await expandEndpoint({ uri: mediatorIdentity.did }, fetchImpl)
    expect(expanded.url).toBe(url)
    expect(expanded.hops[0]!.kid).toBe(mediatorIdentity.xKid)
    expect(expanded.peerKid).toBe(mediatorIdentity.peerKid) // the alias is verified against the keys and the URL
  })
})

describe('both names of the mediator\'s key are accepted', () => {
  async function ask(m: ReturnType<typeof freshMediator>, toKid: string) {
    const bob = peer()
    const plaintext = buildPlaintext(T.MEDIATE_REQUEST, {}, bob.did, m.mediator.did, { returnRoute: 'all' })
    const res = await m.post(packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: bob.xKid, privateKey: bob.xPriv }, [{ kid: toKid, publicKey: m.mediator.xPub }]))
    expect(res.status).toBe(200)
    const { plaintext: bytes, senderKid } = await unpackAuthcrypt(parseJwe(await res.json())!, { kid: bob.xKid, privateKey: bob.xPriv }, async () => m.mediator.xPub)
    return { reply: JSON.parse(new TextDecoder().decode(bytes)) as DidCommPlaintext, senderKid }
  }

  test('a request encrypted to the did:web kid is answered, from the did:web', async () => {
    const m = freshMediator()
    const { reply, senderKid } = await ask(m, m.mediator.xKid)
    expect(reply.type).toBe(T.MEDIATE_GRANT ?? 'https://didcomm.org/coordinate-mediation/3.0/mediate-grant')
    expect(senderKid).toBe(m.mediator.xKid)
    expect(reply.from).toBe(m.mediator.did)
    expect((reply.body as any).routing_did).toEqual([m.mediator.did])
  })

  test('a request encrypted to the did:peer kid (a client that learned it before) is answered too', async () => {
    const m = freshMediator()
    const { reply } = await ask(m, m.mediator.peerKid)
    expect(reply.type).toBe('https://didcomm.org/coordinate-mediation/3.0/mediate-grant')
  })

  test('a Forward wrapped for either kid is queued', async () => {
    const m = freshMediator()
    const bob = peer()
    await m.request(bob, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: bob.did, action: 'add' }] })
    for (const kid of [m.mediator.xKid, m.mediator.peerKid]) {
      const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.did })
      forward.attachments = [{ id: 'inner', data: { json: { n: kid } } }]
      expect((await m.post(packAnoncrypt(utf8(JSON.stringify(forward)), [{ kid, publicKey: m.mediator.xPub }]))).status).toBe(202)
    }
    expect(((await m.request(bob, T.STATUS_REQUEST, {})).body as any).message_count).toBe(2)
  })

  test('the alias is the did:peer of the same key', () => {
    const store = SqliteMediatorStore.memory()
    const peerIdentity = store.loadIdentity('https://mediator.example')
    const web = webMediatorIdentity(peerIdentity, 'https://mediator.example')
    expect(web.xPub).toEqual(peerIdentity.xPub)
    expect(web.peerKid).toBe(peerIdentity.xKid)
    expect(decodePeerDid2(peerIdentity.did).service[0]!.serviceEndpoint.uri).toBe('https://mediator.example')
    const bare = peerMediatorIdentity(peerIdentity)
    expect(bare.did).toBe(peerIdentity.did)
    expect(bare.aliasKids).toEqual([])
  })
})
