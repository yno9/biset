// End-to-end coverage for the blind mediator (src/server/mediator/):
// Coordinate Mediation 2.0, Routing 2.0 Forward, Pickup 3.0, driven through
// the same handle(req, url) a real HTTP server calls, over the production
// SQLite store (in memory).
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { packAuthcrypt, unpackAuthcrypt, b64urlToBytes } from '../src/protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../src/protocol/didcomm/message.ts'
import { serializeLog } from '../src/protocol/webvh/log.ts'
import { buildDidCommLog } from './protocol/support/webvh-log-fixture.ts'
import { deviceLabel, freshMediator, peer, T, utf8 } from './support/mediator.ts'

const DAY = 24 * 60 * 60 * 1000

describe('blind mediator', () => {
  test('mediate-request grants mediation naming the mediator itself as routing_did', async () => {
    const { mediator, request } = freshMediator()
    const grant = await request(peer(), T.MEDIATE_REQUEST, {})
    expect(grant.type).toBe('https://didcomm.org/coordinate-mediation/2.0/mediate-grant')
    expect((grant.body as { routing_did: string }).routing_did).toBe(mediator.did)
  })

  test('full round trip: register, Forward, pick up, ack', async () => {
    const { request, forward } = freshMediator()
    const alice = peer()
    const bob = peer()
    const device = deviceLabel(1)
    const added = await request(bob, T.KEYLIST_UPDATE, { device, updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((added.body as any).updated[0].result).toBe('success')

    const inner = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'hello bob' }, alice.did, bob.did)
    const innerJwe = packAuthcrypt(utf8(JSON.stringify(inner)), { kid: alice.xKid, privateKey: alice.xPriv }, [{ kid: bob.xKid, publicKey: bob.xPub }])
    expect((await forward(bob.xKid, innerJwe)).status).toBe(202)

    expect((await request(bob, T.STATUS_REQUEST, { device }) ).body).toMatchObject({ message_count: 1 })
    const delivery = await request(bob, T.DELIVERY_REQUEST, { device })
    const attachment = delivery.attachments![0]!
    const { plaintext, senderKid } = await unpackAuthcrypt(attachment.data.json as any, { kid: bob.xKid, privateKey: bob.xPriv }, async () => alice.xPub)
    expect(senderKid).toBe(alice.xKid)
    expect(JSON.parse(new TextDecoder().decode(plaintext)).body.content).toBe('hello bob')
    const ack = await request(bob, T.MESSAGES_RECEIVED, { device, message_id_list: [attachment.id] })
    expect((ack.body as any).message_count).toBe(0)
  })

  test('refuses a Forward for a DID nobody registered, with a signed problem-report', async () => {
    const { forward } = freshMediator()
    const res = await forward(peer().xKid, { some: 'ciphertext' })
    expect(res.status).toBe(401)
    expect(res.headers.get('content-type')).toBe('application/didcomm-signed+json')
    const report = JSON.parse(new TextDecoder().decode(b64urlToBytes((await res.json()).payload)))
    expect(report.body.code).toBe('e.p.req.not_enroll')
  })

  test('ownership: a key can only register its own DID, and only touch its own inboxes', async () => {
    const { request, store } = freshMediator()
    const bob = peer()
    const mallory = peer()
    await request(bob, T.KEYLIST_UPDATE, { device: deviceLabel(1), updates: [{ recipient_did: bob.did, action: 'add' }] })

    const squat = await request(mallory, T.KEYLIST_UPDATE, { device: deviceLabel(9), updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((squat.body as any).updated[0].result).toBe('client_error')
    expect(store.listInboxes(bob.did)).toHaveLength(1)

    const peek = await request(mallory, T.STATUS_REQUEST, { recipient_did: bob.did, device: deviceLabel(1) })
    expect(peek.type).toBe(T.PROBLEM_REPORT)
    expect((peek.body as any).code).toBe('e.p.req.not_enroll')
  })

  test('one Forward reaches every device of the DID, stored once; an ack drains only the acking inbox', async () => {
    const { request, forward, store } = freshMediator()
    const bob = peer()
    const [phone, laptop] = [deviceLabel(1), deviceLabel(2)]
    for (const device of [phone, laptop]) await request(bob, T.KEYLIST_UPDATE, { device, updates: [{ recipient_did: bob.did, action: 'add' }] })

    expect((await forward(bob.did, { ciphertext: 'once' })).status).toBe(202)
    expect(store.stats()).toMatchObject({ queuedMessages: 1, pendingDeliveries: 2 })

    const onPhone = await request(bob, T.DELIVERY_REQUEST, { device: phone })
    const onLaptop = await request(bob, T.DELIVERY_REQUEST, { device: laptop })
    expect(onPhone.attachments![0]!.data.json).toEqual({ ciphertext: 'once' })
    expect(onLaptop.attachments![0]!.id).toBe(onPhone.attachments![0]!.id)

    await request(bob, T.MESSAGES_RECEIVED, { device: phone, message_id_list: [onPhone.attachments![0]!.id] })
    expect(store.stats()).toMatchObject({ queuedMessages: 1, pendingDeliveries: 1 })
    expect((await request(bob, T.STATUS_REQUEST, { device: laptop })).body).toMatchObject({ message_count: 1 })
    await request(bob, T.MESSAGES_RECEIVED, { device: laptop, message_id_list: [onPhone.attachments![0]!.id] })
    expect(store.stats()).toMatchObject({ queuedMessages: 0, pendingDeliveries: 0 })
  })

  test('a fourth device is refused with e.p.req.max-devices; keylist-query shows the three; a sibling can remove one', async () => {
    const { request } = freshMediator()
    const bob = peer()
    for (const n of [1, 2, 3]) await request(bob, T.KEYLIST_UPDATE, { device: deviceLabel(n), updates: [{ recipient_did: bob.did, action: 'add' }] })

    const fourth = await request(bob, T.KEYLIST_UPDATE, { device: deviceLabel(4), updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect(fourth.type).toBe(T.PROBLEM_REPORT)
    expect((fourth.body as any).code).toBe('e.p.req.max-devices')
    expect((fourth.body as any).args).toEqual([bob.did, '3', '3'])

    const listed = await request(bob, T.KEYLIST_QUERY, {})
    expect((listed.body as any).keys.map((k: any) => k.device)).toEqual([deviceLabel(1), deviceLabel(2), deviceLabel(3)])
    expect((listed.body as any).keys.every((k: any) => typeof k.last_seen === 'number')).toBe(true)

    const removed = await request(bob, T.KEYLIST_UPDATE, { device: deviceLabel(2), updates: [{ recipient_did: bob.did, action: 'remove' }] })
    expect((removed.body as any).updated[0].result).toBe('success')
    const retried = await request(bob, T.KEYLIST_UPDATE, { device: deviceLabel(4), updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((retried.body as any).updated[0].result).toBe('success')
  })

  test('dormant inboxes get no copies and are told they missed some; with every inbox dormant the latest still collects', async () => {
    const { request, forward, store } = freshMediator()
    const bob = peer()
    const now = Date.now()
    store.addInbox(bob.did, deviceLabel(1), bob.xKid, now - 20 * DAY)
    store.addInbox(bob.did, deviceLabel(2), bob.xKid, now - 30 * DAY)

    // Both dormant: the most recently active one still collects.
    await forward(bob.did, { n: 1 })
    expect(store.count(bob.did, deviceLabel(1))).toBe(1)
    expect(store.count(bob.did, deviceLabel(2))).toBe(0)

    // One live device: the dormant one is skipped and flagged.
    store.addInbox(bob.did, deviceLabel(3), bob.xKid, now)
    await forward(bob.did, { n: 2 })
    expect(store.count(bob.did, deviceLabel(3))).toBe(1)
    expect(store.count(bob.did, deviceLabel(1))).toBe(1)
    // Retention then empties every dormant inbox that is not the latest.
    store.expire(now)
    expect(store.count(bob.did, deviceLabel(1))).toBe(0)
    const status = await request(bob, T.STATUS_REQUEST, { device: deviceLabel(1) })
    expect(status.body).toMatchObject({ message_count: 0, missed: true })
    expect((await request(bob, T.STATUS_REQUEST, { device: deviceLabel(1) })).body).not.toHaveProperty('missed')
  })

  test('a full inbox is skipped without blocking its siblings; the sender is refused only when none can take it', async () => {
    const { forward, store } = freshMediator({ maxQueueItemsPerInbox: 1 })
    const bob = peer()
    store.addInbox(bob.did, deviceLabel(1), bob.xKid)
    store.addInbox(bob.did, deviceLabel(2), bob.xKid)
    expect((await forward(bob.did, { n: 1 })).status).toBe(202)
    store.acknowledge(bob.did, deviceLabel(2), store.peek(bob.did, deviceLabel(2), 10).map(m => m.id))
    expect((await forward(bob.did, { n: 2 })).status).toBe(202)
    expect(store.count(bob.did, deviceLabel(1))).toBe(1)
    expect(store.count(bob.did, deviceLabel(2))).toBe(1)
    expect((await forward(bob.did, { n: 3 })).status).toBe(503)
  })

  test('did:webvh: authenticated only against a pushed log; a stale log is ignored', async () => {
    const { mediator, post, request, pushLog } = freshMediator()
    const rootPrivateKey = new Uint8Array(32).fill(7)
    const deviceX = x25519.utils.randomSecretKey()
    const { did, log } = buildDidCommLog({
      rootPrivateKey, rootPublicKey: ed25519.getPublicKey(rootPrivateKey),
      keyAgreementKeys: [{ fragment: 'k_device', x25519PublicKey: x25519.getPublicKey(deviceX) }],
    })
    const device = { did, xKid: `${did}#k_device`, xPriv: deviceX }

    // Before the log: the mediator cannot know this key, and says so.
    const blind = buildPlaintext(T.MEDIATE_REQUEST, {}, did, mediator.did)
    const unknown = await post(packAuthcrypt(utf8(JSON.stringify(blind)), { kid: device.xKid, privateKey: deviceX }, [{ kid: mediator.xKid, publicKey: mediator.xPub }]))
    expect(unknown.status).toBe(401)
    expect((await unknown.json()).code).toBe('e.p.req.webvh-log-required')

    expect(await (await pushLog(serializeLog(log))).json()).toMatchObject({ did, version: 1, outcome: 'stored' })
    expect(await (await pushLog(serializeLog(log))).json()).toMatchObject({ outcome: 'stale' })
    expect((await pushLog('not a log')).status).toBe(400)
    const added = await request(device, T.KEYLIST_UPDATE, { device: deviceLabel(1), updates: [{ recipient_did: did, action: 'add' }] })
    expect((added.body as any).updated[0].result).toBe('success')
  })

  test('a newer did:webvh state revokes inboxes registered with a key it no longer lists', () => {
    const { store } = freshMediator()
    const did = 'did:webvh:scid:example.test'
    expect(store.recordWebvhState(did, 1, { [`${did}#k_a`]: '00', [`${did}#k_b`]: '01' })).toBe('stored')
    store.addInbox(did, deviceLabel(1), `${did}#k_a`)
    store.addInbox(did, deviceLabel(2), `${did}#k_b`)
    expect(store.recordWebvhState(did, 2, { [`${did}#k_a`]: '00' })).toBe('stored')
    expect(store.listInboxes(did).map(inbox => inbox.device)).toEqual([deviceLabel(1)])
    expect(store.webvhKey(did, `${did}#k_b`)).toBeUndefined()
    expect(store.recordWebvhState(did, 1, { [`${did}#k_b`]: '01' })).toBe('stale')
  })
})
