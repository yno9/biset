// End-to-end coverage for the standalone blind mediator (src/mediator/) --
// Coordinate Mediation 2.0 (mediate-request/keylist-update), Routing 2.0
// Forward, and Pickup 3.0 (status/delivery-request/messages-received), all
// driven over the same createMediator({ mediator, ... }).handle(req, url)
// entrypoint a real HTTP server would call. Both test clients are did:peer
// identities -- deliberately not did:webvh biset users, since the whole
// point of a blind mediator (ARC.md's 2026-08-27 redesign) is that it works
// for ANY DIDComm agent, not just biset's own.
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../src/shared/didcomm/peer.ts'
import { createMediator } from '../src/server/didcomm-mediator/server.ts'
import {
  packAuthcrypt, unpackAuthcrypt, packAnoncrypt, b64urlToBytes, parseJwe,
} from '../src/shared/didcomm/crypto.ts'
import { buildPlaintext, type DidCommPlaintext } from '../src/shared/didcomm/message.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b)

function freshMediator() {
  const mediator = generatePeerIdentity({ uri: 'https://mediator.test.example', accept: ['didcomm/v2'] })
  const { handle } = createMediator({ mediator })
  const post = (body: unknown) => handle(new Request('https://mediator.test.example/', { method: 'POST', body: JSON.stringify(body) }), new URL('https://mediator.test.example/'))
  return { mediator, post }
}

/** Authcrypts `type`/`body` from `sender` to the mediator, POSTs it, and
 * unpacks the mediator's authcrypt'd reply back to `sender`. */
async function request(post: (body: unknown) => Promise<Response | null>, mediator: ReturnType<typeof generatePeerIdentity>, sender: ReturnType<typeof generatePeerIdentity>, type: string, body: unknown): Promise<DidCommPlaintext> {
  const plaintext = buildPlaintext(type, body, sender.did, mediator.did)
  const jwe = packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: sender.xKid, privateKey: sender.xPriv }, { kid: mediator.xKid, publicKey: mediator.xPub })
  const res = await post(jwe)
  expect(res).not.toBeNull()
  expect(res!.status).toBe(200)
  const replyJwe = parseJwe(await res!.json())
  expect(replyJwe).not.toBeNull()
  const { plaintext: replyBytes } = await unpackAuthcrypt(replyJwe!, { kid: sender.xKid, privateKey: sender.xPriv }, async () => mediator.xPub)
  return JSON.parse(fromUtf8(replyBytes))
}

describe('standalone mediator (Coordinate Mediation 2.0 + Routing 2.0 + Pickup 3.0)', () => {
  test('mediate-request grants mediation naming the mediator itself as routing_did', async () => {
    const { mediator, post } = freshMediator()
    const bob = generatePeerIdentity()
    const grant = await request(post, mediator, bob, 'https://didcomm.org/coordinate-mediation/2.0/mediate-request', {})
    expect(grant.type).toBe('https://didcomm.org/coordinate-mediation/2.0/mediate-grant')
    expect((grant.body as any).routing_did).toBe(mediator.did)
  })

  test('full round-trip: register, Forward-deliver, pick up, and ack', async () => {
    const { mediator, post } = freshMediator()
    const alice = generatePeerIdentity()
    const bob = generatePeerIdentity()

    await request(post, mediator, bob, 'https://didcomm.org/coordinate-mediation/2.0/mediate-request', {})
    const updateReply = await request(post, mediator, bob, 'https://didcomm.org/coordinate-mediation/2.0/keylist-update', {
      updates: [{ recipient_did: bob.xKid, action: 'add' }],
    })
    expect((updateReply.body as any).updated[0].result).toBe('success')

    // Alice authcrypts a message to Bob, then anoncrypts a Forward envelope
    // to the mediator naming Bob's kid as `next` -- exactly what a sender's
    // send-message.ts would build (Phase 5, not yet wired). The mediator
    // must never be able to read the inner authcrypt'd payload.
    const inner = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'hello bob' }, alice.did, bob.did)
    const innerJwe = packAuthcrypt(utf8(JSON.stringify(inner)), { kid: alice.xKid, privateKey: alice.xPriv }, { kid: bob.xKid, publicKey: bob.xPub })
    const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.xKid })
    forward.attachments = [{ id: 'inner', data: { json: innerJwe } }]
    const forwardJwe = packAnoncrypt(utf8(JSON.stringify(forward)), { kid: mediator.xKid, publicKey: mediator.xPub })
    const forwardRes = await post(forwardJwe)
    expect(forwardRes!.status).toBe(202)

    const status = await request(post, mediator, bob, 'https://didcomm.org/messagepickup/3.0/status-request', {})
    expect((status.body as any).message_count).toBe(1)

    const delivery = await request(post, mediator, bob, 'https://didcomm.org/messagepickup/3.0/delivery-request', {})
    expect(delivery.type).toBe('https://didcomm.org/messagepickup/3.0/delivery')
    const attachment = delivery.attachments![0]!
    const deliveredJwe = attachment.data.json as any
    const { plaintext: innerBytes, senderKid } = await unpackAuthcrypt(deliveredJwe, { kid: bob.xKid, privateKey: bob.xPriv }, async () => alice.xPub)
    const delivered = JSON.parse(fromUtf8(innerBytes))
    expect(senderKid).toBe(alice.xKid)
    expect((delivered.body as any).content).toBe('hello bob')

    const ack = await request(post, mediator, bob, 'https://didcomm.org/messagepickup/3.0/messages-received', { message_id_list: [attachment.id] })
    expect((ack.body as any).message_count).toBe(0)
    const statusAfter = await request(post, mediator, bob, 'https://didcomm.org/messagepickup/3.0/status-request', {})
    expect((statusAfter.body as any).message_count).toBe(0)
  })

  test('refuses a Forward to a kid nobody registered, with a signed (not encrypted) problem-report', async () => {
    const { mediator, post } = freshMediator()
    const stranger = generatePeerIdentity()
    const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: stranger.xKid })
    forward.attachments = [{ id: 'inner', data: { json: { some: 'ciphertext' } } }]
    const forwardJwe = packAnoncrypt(utf8(JSON.stringify(forward)), { kid: mediator.xKid, publicKey: mediator.xPub })
    const res = await post(forwardJwe)
    expect(res!.status).toBe(401)
    expect(res!.headers.get('content-type')).toBe('application/didcomm-signed+json')
    const jws = await res!.json()
    const report = JSON.parse(fromUtf8(b64urlToBytes(jws.payload)))
    expect(report.body.code).toBe('e.p.req.not_enroll')
  })

  test('a registered client cannot collect or ack another client\'s queued messages', async () => {
    const { mediator, post } = freshMediator()
    const bob = generatePeerIdentity()
    const mallory = generatePeerIdentity()
    await request(post, mediator, bob, 'https://didcomm.org/coordinate-mediation/2.0/mediate-request', {})
    await request(post, mediator, bob, 'https://didcomm.org/coordinate-mediation/2.0/keylist-update', { updates: [{ recipient_did: bob.xKid, action: 'add' }] })
    await request(post, mediator, mallory, 'https://didcomm.org/coordinate-mediation/2.0/mediate-request', {})
    await request(post, mediator, mallory, 'https://didcomm.org/coordinate-mediation/2.0/keylist-update', { updates: [{ recipient_did: mallory.xKid, action: 'add' }] })

    const denied = await request(post, mediator, mallory, 'https://didcomm.org/messagepickup/3.0/status-request', { recipient_did: bob.xKid })
    expect(denied.type).toBe('https://didcomm.org/report-problem/2.0/problem-report')
    expect((denied.body as any).code).toBe('e.p.req.not_enroll')
  })

  test('keylist-query returns exactly what this client itself registered', async () => {
    const { mediator, post } = freshMediator()
    const bob = generatePeerIdentity()
    await request(post, mediator, bob, 'https://didcomm.org/coordinate-mediation/2.0/mediate-request', {})
    await request(post, mediator, bob, 'https://didcomm.org/coordinate-mediation/2.0/keylist-update', { updates: [{ recipient_did: bob.xKid, action: 'add' }] })
    const keylist = await request(post, mediator, bob, 'https://didcomm.org/coordinate-mediation/2.0/keylist-query', {})
    expect((keylist.body as any).keys).toEqual([{ recipient_did: bob.xKid }])
  })
})
