// End-to-end coverage for the blind mediator (src/server/mediator/):
// Coordinate Mediation 3.0, Routing 2.0 Forward, Pickup 3.0, Discover
// Features 2.0, driven through
// the same handle(req, url) a real HTTP server calls, over the production
// SQLite store (in memory).
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { packAnoncrypt, packAuthcrypt, unpackAuthcrypt, b64urlToBytes } from '../src/protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../src/protocol/didcomm/message.ts'
import { queuedMessageOf } from '../src/protocol/didcomm/mediator-pickup.ts'
import { defaultDeviceLabel } from '../src/protocol/didcomm/mediator-device.ts'
import { WebvhUnavailable, type WebvhState } from '../src/server/mediator/webvh-state.ts'
import { SqliteMediatorStore } from '../src/server/mediator/sqlite-store.ts'
import { serializeLog } from '../src/protocol/webvh/log.ts'
import { buildDidCommLog, fakeAnchor } from './protocol/support/webvh-log-fixture.ts'
import { pushWebvhLog } from '../src/protocol/didcomm/mediator-coordinate.ts'
import { createGenesis } from '../src/client/identity/webvh/create-genesis.ts'
import { migrateWebvhLocation } from '../src/client/identity/webvh/migrate.ts'
import { fetchCurrentLog } from '../src/client/identity/webvh/log-io.ts'
import { encodeMultikey } from '../src/protocol/webvh/multikey.ts'
import { multikeyHashBase58 } from '../src/protocol/webvh/hash.ts'
import { deviceLabel, freshMediator, peer, T, utf8 } from './support/mediator.ts'

const DAY = 24 * 60 * 60 * 1000

describe('blind mediator', () => {
  test('mediate-request grants mediation naming the mediator itself as routing_did', async () => {
    const { mediator, request } = freshMediator()
    const grant = await request(peer(), T.MEDIATE_REQUEST, {})
    expect(grant.type).toBe('https://didcomm.org/coordinate-mediation/3.0/mediate-grant')
    expect((grant.body as { routing_did: string[] }).routing_did).toEqual([mediator.did])
  })

  test('full round trip: register, Forward, pick up, ack', async () => {
    const { request, forward } = freshMediator()
    const alice = peer()
    const bob = peer()
    const device = deviceLabel(1)
    const added = await request(bob, T.RECIPIENT_UPDATE, { device, updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((added.body as any).updated[0].result).toBe('success')

    const inner = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'hello bob' }, alice.did, bob.did)
    const innerJwe = packAuthcrypt(utf8(JSON.stringify(inner)), { kid: alice.xKid, privateKey: alice.xPriv }, [{ kid: bob.xKid, publicKey: bob.xPub }])
    expect((await forward(bob.xKid, innerJwe)).status).toBe(202)

    expect((await request(bob, T.STATUS_REQUEST, { device }) ).body).toMatchObject({ message_count: 1 })
    const delivery = await request(bob, T.DELIVERY_REQUEST, { device })
    const attachment = delivery.attachments![0]!
    const { plaintext, senderKid } = await unpackAuthcrypt(queuedMessageOf(attachment) as any, { kid: bob.xKid, privateKey: bob.xPriv }, async () => alice.xPub)
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
    expect(report.body.code).toBe('e.m.req.not-enrolled')
  })

  test('ownership: a key can only register its own DID, and only touch its own inboxes', async () => {
    const { request, store } = freshMediator()
    const bob = peer()
    const mallory = peer()
    await request(bob, T.RECIPIENT_UPDATE, { device: deviceLabel(1), updates: [{ recipient_did: bob.did, action: 'add' }] })

    const squat = await request(mallory, T.RECIPIENT_UPDATE, { device: deviceLabel(9), updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((squat.body as any).updated[0].result).toBe('client_error')
    expect(store.listInboxes(bob.did)).toHaveLength(1)

    const peek = await request(mallory, T.STATUS_REQUEST, { recipient_did: bob.did, device: deviceLabel(1) })
    expect(peek.type).toBe(T.PROBLEM_REPORT)
    expect((peek.body as any).code).toBe('e.m.req.not-enrolled')
  })

  test('one Forward reaches every device of the DID, stored once; an ack drains only the acking inbox', async () => {
    const { request, forward, store } = freshMediator()
    const bob = peer()
    const [phone, laptop] = [deviceLabel(1), deviceLabel(2)]
    for (const device of [phone, laptop]) await request(bob, T.RECIPIENT_UPDATE, { device, updates: [{ recipient_did: bob.did, action: 'add' }] })

    expect((await forward(bob.did, { ciphertext: 'once' })).status).toBe(202)
    expect(store.stats()).toMatchObject({ queuedMessages: 1, pendingDeliveries: 2 })

    const onPhone = await request(bob, T.DELIVERY_REQUEST, { device: phone })
    const onLaptop = await request(bob, T.DELIVERY_REQUEST, { device: laptop })
    expect(queuedMessageOf(onPhone.attachments![0]!)).toEqual({ ciphertext: 'once' })
    expect(onLaptop.attachments![0]!.id).toBe(onPhone.attachments![0]!.id)

    await request(bob, T.MESSAGES_RECEIVED, { device: phone, message_id_list: [onPhone.attachments![0]!.id] })
    expect(store.stats()).toMatchObject({ queuedMessages: 1, pendingDeliveries: 1 })
    expect((await request(bob, T.STATUS_REQUEST, { device: laptop })).body).toMatchObject({ message_count: 1 })
    await request(bob, T.MESSAGES_RECEIVED, { device: laptop, message_id_list: [onPhone.attachments![0]!.id] })
    expect(store.stats()).toMatchObject({ queuedMessages: 0, pendingDeliveries: 0 })
  })

  test('a fourth device is refused with e.m.req.max-devices; recipient-query shows the three; a sibling can remove one', async () => {
    const { request } = freshMediator()
    const bob = peer()
    for (const n of [1, 2, 3]) await request(bob, T.RECIPIENT_UPDATE, { device: deviceLabel(n), updates: [{ recipient_did: bob.did, action: 'add' }] })

    const fourth = await request(bob, T.RECIPIENT_UPDATE, { device: deviceLabel(4), updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect(fourth.type).toBe(T.PROBLEM_REPORT)
    expect((fourth.body as any).code).toBe('e.m.req.max-devices')
    expect((fourth.body as any).args).toEqual([bob.did, '3', '3'])

    // One entry for the DID, with when each inbox was last used -- never its
    // label: a holder of the DID's key (a removed device, for a shared
    // did:peer) must not learn the label of a remaining device's inbox and
    // remove it.
    const listed = await request(bob, T.RECIPIENT_QUERY, {})
    expect((listed.body as any).dids).toHaveLength(1)
    const entry = (listed.body as any).dids[0]
    expect(entry.recipient_did).toBe(bob.did)
    expect(entry.devices).toHaveLength(3)
    expect(entry.devices.every((d: any) => typeof d.last_seen === 'number' && d.device === undefined)).toBe(true)

    const removed = await request(bob, T.RECIPIENT_UPDATE, { device: deviceLabel(2), updates: [{ recipient_did: bob.did, action: 'remove' }] })
    expect((removed.body as any).updated[0].result).toBe('success')
    const retried = await request(bob, T.RECIPIENT_UPDATE, { device: deviceLabel(4), updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((retried.body as any).updated[0].result).toBe('success')
  })

  test('recipient-query pages over DIDs with paginate {limit, offset}', async () => {
    const { request } = freshMediator()
    const bob = peer()
    for (const n of [1, 2, 3]) await request(bob, T.RECIPIENT_UPDATE, { device: deviceLabel(n), updates: [{ recipient_did: bob.did, action: 'add' }] })
    const first = await request(bob, T.RECIPIENT_QUERY, { paginate: { limit: 1, offset: 0 } })
    expect((first.body as any).dids).toHaveLength(1)
    expect((first.body as any).pagination).toEqual({ count: 1, offset: 0, remaining: 0 })
    const beyond = await request(bob, T.RECIPIENT_QUERY, { paginate: { limit: 1, offset: 1 } })
    expect((beyond.body as any).dids).toHaveLength(0)
    expect((beyond.body as any).pagination).toEqual({ count: 0, offset: 1, remaining: 0 })
  })

  test('recipient-query lists nothing for a DID with no inbox', async () => {
    const { request } = freshMediator()
    expect(((await request(peer(), T.RECIPIENT_QUERY, {})).body as any).dids).toEqual([])
  })

  test('Discover Features discloses max_receive_bytes and the protocols it speaks, matching * wildcards', async () => {
    const { request } = freshMediator({ maxMessageBytes: 65_536 })
    const bob = peer()
    const constraint = await request(bob, T.DISCOVER_FEATURES_QUERIES, { queries: [{ 'feature-type': 'constraint', match: 'max_receive_bytes' }] })
    expect(constraint.type).toBe(T.DISCOVER_FEATURES_DISCLOSE)
    expect((constraint.body as any).disclosures).toEqual([{ 'feature-type': 'constraint', id: 'max_receive_bytes', max_receive_bytes: '65536' }])
    const protocols = await request(bob, T.DISCOVER_FEATURES_QUERIES, { queries: [{ 'feature-type': 'protocol', match: 'https://didcomm.org/coordinate-mediation/*' }, { 'feature-type': 'protocol', match: 'https://didcomm.org/tictactoe/1.*' }] })
    expect((protocols.body as any).disclosures).toEqual([{ 'feature-type': 'protocol', id: 'https://didcomm.org/coordinate-mediation/3.0', roles: ['mediator'] }])
    const unknown = await request(bob, T.DISCOVER_FEATURES_QUERIES, { queries: [{ 'feature-type': 'goal-code', match: '*' }] })
    expect((unknown.body as any).disclosures).toEqual([])
  })

  test('a Forward over max_receive_bytes is refused with 413 and message_too_big', async () => {
    const { request, forward } = freshMediator({ maxMessageBytes: 2048, maxQueueBytesPerInbox: 4096 })
    const bob = peer()
    await request(bob, T.RECIPIENT_UPDATE, { device: deviceLabel(1), updates: [{ recipient_did: bob.did, action: 'add' }] })
    const res = await forward(bob.did, { opaque: 'x'.repeat(4096) })
    expect(res.status).toBe(413)
    // a transport-level error whose body is the standard problem report, referring to the forward
    const report = await res.json() as { type: string; pthid: string; ack: string[]; lang: string; body: { code: string; comment: string; args: string[] } }
    expect(res.headers.get('content-type')).toBe('application/didcomm-plain+json')
    expect(report.type).toBe('https://didcomm.org/report-problem/2.0/problem-report')
    expect(report.body.code).toBe('e.m.me.res.storage.message_too_big')
    expect(report.body.comment).toContain('{1}') // fixed text; the value is in args
    expect(report.body.args).toHaveLength(1)
    expect(report.pthid).toBeTruthy()
    expect(report.ack).toHaveLength(1)
    expect(report.lang).toBe('en')
  })

  test('did:webvh: a log of a DID that moved domains (genesis names the old one) is accepted under its current DID', async () => {
    // Found live 2026-10-03: did.md creates the identity under an alias and
    // later moves it to its real hostname. The genesis entry keeps the old
    // domain; the DID is whatever the latest entry says.
    const { pushLog } = freshMediator()
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const spare = ed25519.utils.randomSecretKey()
    const nextSpare = ed25519.utils.randomSecretKey()
    const anchor = fakeAnchor()
    const { did: oldDid } = await createGenesis({
      domain: 'ex.alias', rootPrivateKey, rootPublicKey,
      nextKeyHash: multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(spare))), fetch: anchor.fetch,
    })
    const { newDid } = await migrateWebvhLocation({
      oldDid, newDomain: 'c8de.did.md',
      signingPrivateKey: spare, signingPublicKey: ed25519.getPublicKey(spare),
      nextKeyHash: multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(nextSpare))), fetch: anchor.fetch,
    })
    const { entries } = await fetchCurrentLog(newDid, anchor.fetch)
    expect((entries[0]!.state as { id: string }).id).toBe(oldDid)
    expect(await (await pushLog(serializeLog(entries))).json()).toMatchObject({ did: newDid, outcome: 'stored' })
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
    expect((await unknown.json()).body.code).toBe('e.m.did.log-required')

    expect(await (await pushLog(serializeLog(log))).json()).toMatchObject({ did, version: 1, outcome: 'stored' })
    expect(await (await pushLog(serializeLog(log))).json()).toMatchObject({ outcome: 'stale' })
    expect((await pushLog('not a log')).status).toBe(400)
    const added = await request(device, T.RECIPIENT_UPDATE, { device: deviceLabel(1), updates: [{ recipient_did: did, action: 'add' }] })
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

// What a standard DIDComm client sends: the bodies exactly as Coordinate
// Mediation 3.0 and Pickup 3.0 define them, with no biset `device` label.
describe('a standard client of the mediator', () => {
  test('registers, is queued to, picks up and acknowledges without naming a device', async () => {
    const { request, forward, store } = freshMediator()
    const bob = peer()
    const update = await request(bob, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((update.body as any).updated).toEqual([{ recipient_did: bob.did, action: 'add', result: 'success' }])
    // one inbox per sending key: derived from the kid
    expect(store.listInboxes(bob.did)).toHaveLength(1)
    expect(store.hasInbox(bob.did, defaultDeviceLabel(bob.xKid))).toBe(true)

    expect((await forward(bob.did, { ciphertext: 'x' })).status).toBe(202)
    expect((await request(bob, T.STATUS_REQUEST, {})).body).toMatchObject({ recipient_did: bob.did, message_count: 1 })

    const delivery = await request(bob, T.DELIVERY_REQUEST, { limit: 10 })
    expect(delivery.type).toBe('https://didcomm.org/messagepickup/3.0/delivery')
    expect(queuedMessageOf(delivery.attachments![0]!)).toEqual({ ciphertext: 'x' })
    const ack = await request(bob, T.MESSAGES_RECEIVED, { message_id_list: [delivery.attachments![0]!.id] })
    expect((ack.body as any).message_count).toBe(0)
  })

  test('naming a `device` still works, and is a different inbox from the default one', async () => {
    const { request, forward, store } = freshMediator()
    const bob = peer()
    await request(bob, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: bob.did, action: 'add' }] })
    await request(bob, T.RECIPIENT_UPDATE, { device: deviceLabel(1), updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect(store.listInboxes(bob.did)).toHaveLength(2)
    await forward(bob.did, { ciphertext: 'both' })
    expect((await request(bob, T.STATUS_REQUEST, {})).body).toMatchObject({ message_count: 1 })
    expect((await request(bob, T.STATUS_REQUEST, { device: deviceLabel(1) })).body).toMatchObject({ message_count: 1 })
  })

  test('a `device` that is not a valid label is refused', async () => {
    const { request } = freshMediator()
    const bob = peer()
    const refused = await request(bob, T.RECIPIENT_UPDATE, { device: 'x', updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect(refused.type).toBe(T.PROBLEM_REPORT)
    expect((refused.body as any).code).toBe('e.m.msg.invalid-device')
  })

  test('a client with no inbox is told so, not given someone else\'s', async () => {
    const { request } = freshMediator()
    const stranger = peer()
    const reply = await request(stranger, T.STATUS_REQUEST, {})
    expect(reply.type).toBe(T.PROBLEM_REPORT)
    expect((reply.body as any).code).toBe('e.m.req.not-enrolled')
  })

  test('delivery carries each message as `data.base64` (Pickup 3.0), and names a recipient_did only when asked', async () => {
    const { request, forward } = freshMediator()
    const bob = peer()
    await request(bob, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: bob.did, action: 'add' }] })
    await forward(bob.did, { ciphertext: 'a' })
    const plain = await request(bob, T.DELIVERY_REQUEST, { limit: 10 })
    const attachment = plain.attachments![0]!
    expect(typeof attachment.data.base64).toBe('string')
    expect(attachment.data.json).toBeUndefined()
    expect(attachment.media_type).toBe('application/didcomm-encrypted+json')
    expect(JSON.parse(new TextDecoder().decode(b64urlToBytes(attachment.data.base64!)))).toEqual({ ciphertext: 'a' })
    expect(plain.body).toEqual({})
    const named = await request(bob, T.DELIVERY_REQUEST, { limit: 10, recipient_did: bob.did })
    expect((named.body as any).recipient_did).toBe(bob.did)
  })

  test('the reader takes base64, and embedded JSON from mediators that use it; anything else is an error', () => {
    expect(queuedMessageOf({ data: { json: { a: 1 } } })).toEqual({ a: 1 })
    expect(queuedMessageOf({ data: { base64: 'eyJhIjoxfQ' } })).toEqual({ a: 1 })
    expect(() => queuedMessageOf({ data: { base64: 'not base64url!' } })).toThrow()
    expect(queuedMessageOf({})).toBeUndefined()
  })

  test('every status says whether live delivery is on (always off over HTTP)', async () => {
    const { request, forward } = freshMediator()
    const bob = peer()
    await request(bob, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((await request(bob, T.STATUS_REQUEST, {})).body).toMatchObject({ live_delivery: false, message_count: 0 })
    await forward(bob.did, { ciphertext: 'q' })
    const ack = await request(bob, T.MESSAGES_RECEIVED, { message_id_list: [(await request(bob, T.DELIVERY_REQUEST, { limit: 1 })).attachments![0]!.id] })
    expect((ack.body as any).live_delivery).toBe(false)
  })

  test('recipient-query answers with the DID, and the last use of each of its inboxes as an extension', async () => {
    const { request } = freshMediator()
    const bob = peer()
    await request(bob, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: bob.did, action: 'add' }] })
    const listed = await request(bob, T.RECIPIENT_QUERY, {})
    expect((listed.body as any).dids).toEqual([{ recipient_did: bob.did, devices: [{ last_seen: expect.any(Number) }] }])
  })
})

// did:webvh keys, learned the way a DIDComm agent learns a sender's keys: the
// mediator resolves the DID itself (webvh-state.ts) -- nothing is pushed.
describe('a mediator that resolves did:webvh', () => {
  const DID = 'did:webvh:scid:alice.example'
  const hex = (key: Uint8Array) => [...key].map(x => x.toString(16).padStart(2, '0')).join('')
  const device = (fragment: string) => {
    const xPriv = x25519.utils.randomSecretKey()
    return { holder: { did: DID, xKid: `${DID}#${fragment}`, xPriv }, hex: hex(x25519.getPublicKey(xPriv)) }
  }
  const add = { updates: [{ recipient_did: DID, action: 'add' }] }
  const stateWith = (version: number, keys: Record<string, string>): WebvhState => ({ did: DID, versionNumber: version, keys })

  /** A mediator whose resolver answers from `world`, counts its calls, and runs on a clock the test moves. */
  function resolving(world: { state: WebvhState | null; down?: boolean }, options: { fresh?: number; retry?: number; stale?: number } = {}) {
    const calls = { n: 0 }
    const clock = { now: Date.now() } // the store stamps real time, so the test clock starts there
    const m = freshMediator({}, SqliteMediatorStore.memory(), {
      now: () => clock.now, webvhFreshMs: options.fresh ?? 300_000, webvhRetryMs: options.retry ?? 10_000, webvhStaleMs: options.stale ?? 3_600_000,
      resolveWebvh: async () => { calls.n++; if (world.down) throw new WebvhUnavailable('network down'); return world.state },
    })
    return { ...m, calls, clock }
  }

  /** One raw authcrypt request, for answers that are not a DIDComm reply (HTTP errors). */
  async function raw(m: ReturnType<typeof resolving>, from: { did: string; xKid: string; xPriv: Uint8Array }, type: string, body: unknown) {
    const plaintext = buildPlaintext(type, body, from.did, m.mediator.did, { returnRoute: 'all' })
    return m.post(packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: from.xKid, privateKey: from.xPriv }, [{ kid: m.mediator.xKid, publicKey: m.mediator.xPub }]))
  }

  test('registers a device whose key the DID lists, with nothing pushed', async () => {
    const a = device('k_a')
    const m = resolving({ state: stateWith(1, { [`${DID}#k_a`]: a.hex }) })
    const reply = await m.request(a.holder, T.RECIPIENT_UPDATE, add)
    expect((reply.body as any).updated[0].result).toBe('success')
    expect(m.store.listInboxes(DID)).toHaveLength(1)
    expect(m.calls.n).toBe(1)
  })

  test('a key the DID does not list is refused 401, and is not asked about again within the retry window', async () => {
    const a = device('k_a')
    const m = resolving({ state: stateWith(1, { [`${DID}#k_other`]: '00'.repeat(32) }) })
    const first = await raw(m, a.holder, T.RECIPIENT_UPDATE, add)
    expect(first.status).toBe(401)
    expect((await first.json()).body.code).toBe('e.m.trust.sender-key-not-listed')
    expect((await raw(m, a.holder, T.RECIPIENT_UPDATE, add)).status).toBe(401)
    expect(m.calls.n).toBe(1) // the second one did not dial out again
    m.clock.now += 11_000
    expect((await raw(m, a.holder, T.RECIPIENT_UPDATE, add)).status).toBe(401)
    expect(m.calls.n).toBe(2)
  })

  test('a DID with no log at all is refused 401', async () => {
    const a = device('k_a')
    const m = resolving({ state: null })
    expect((await raw(m, a.holder, T.RECIPIENT_UPDATE, add)).status).toBe(401)
  })

  test('a key added to the DID later is found: an unlisted key triggers a fresh resolve', async () => {
    const a = device('k_a'); const b = device('k_b')
    const world = { state: stateWith(1, { [`${DID}#k_a`]: a.hex }) as WebvhState | null }
    const m = resolving(world)
    await m.request(a.holder, T.RECIPIENT_UPDATE, add)
    world.state = stateWith(2, { [`${DID}#k_a`]: a.hex, [`${DID}#k_b`]: b.hex })
    m.clock.now += 11_000
    const reply = await m.request(b.holder, T.RECIPIENT_UPDATE, { device: deviceLabel(2), ...add })
    expect((reply.body as any).updated[0].result).toBe('success')
  })

  test('a state is trusted for the freshness window, then the DID is resolved again', async () => {
    const a = device('k_a')
    const m = resolving({ state: stateWith(1, { [`${DID}#k_a`]: a.hex }) }, { fresh: 60_000, retry: 1000 })
    await m.request(a.holder, T.RECIPIENT_UPDATE, add)
    m.clock.now += 30_000
    await m.request(a.holder, T.STATUS_REQUEST, {})
    expect(m.calls.n).toBe(1)
    m.clock.now += 40_000
    await m.request(a.holder, T.STATUS_REQUEST, {})
    expect(m.calls.n).toBe(2)
  })

  test('refreshWebvh revokes the inbox of a device its DID no longer lists, with what it held', async () => {
    const a = device('k_a'); const b = device('k_b')
    const world = { state: stateWith(1, { [`${DID}#k_a`]: a.hex, [`${DID}#k_b`]: b.hex }) as WebvhState | null }
    const m = resolving(world, { retry: 0 })
    await m.request(a.holder, T.RECIPIENT_UPDATE, { device: deviceLabel(1), ...add })
    await m.request(b.holder, T.RECIPIENT_UPDATE, { device: deviceLabel(2), ...add })
    await m.forward(DID, { ciphertext: 'for both' })
    expect(m.store.stats()).toMatchObject({ inboxes: 2, pendingDeliveries: 2 })

    world.state = stateWith(2, { [`${DID}#k_a`]: a.hex }) // k_b was removed from the DID
    expect(await m.refreshWebvh()).toEqual({ checked: 1, revoked: 1 })
    expect(m.store.listInboxes(DID).map(inbox => inbox.device)).toEqual([deviceLabel(1)])
    expect(m.store.stats()).toMatchObject({ inboxes: 1, pendingDeliveries: 1 })
    // and the removed device can no longer even ask
    expect((await raw(m, b.holder, T.STATUS_REQUEST, { device: deviceLabel(2) })).status).toBe(401)
  })

  test('when the network is down: 503 for a DID never seen, and a recently confirmed state still stands', async () => {
    const a = device('k_a')
    const world = { state: stateWith(1, { [`${DID}#k_a`]: a.hex }) as WebvhState | null, down: true }
    const m = resolving(world, { fresh: 60_000, retry: 0, stale: 3_600_000 })
    const unknown = await raw(m, a.holder, T.RECIPIENT_UPDATE, add)
    expect(unknown.status).toBe(503)
    expect((await unknown.json()).body.code).toBe('e.m.me.res.net')

    world.down = false
    await m.request(a.holder, T.RECIPIENT_UPDATE, add)
    world.down = true
    m.clock.now += 120_000 // not fresh any more, the network is down, but confirmed within the hour
    expect(((await m.request(a.holder, T.STATUS_REQUEST, {})).body as any).message_count).toBe(0)
    m.clock.now += 4_000_000 // beyond the stale window
    expect((await raw(m, a.holder, T.STATUS_REQUEST, {})).status).toBe(503)
  })

  test('a log pushed to POST /webvh-log still works (kept, not DIDComm); the resolver is only asked', async () => {
    const root = ed25519.utils.randomSecretKey()
    const xPriv = x25519.utils.randomSecretKey()
    const { did, log } = buildDidCommLog({ rootPrivateKey: root, rootPublicKey: ed25519.getPublicKey(root), keyAgreementKeys: [{ fragment: 'k_a', x25519PublicKey: x25519.getPublicKey(xPriv) }], endpointUri: 'https://x.example', domain: 'alice.example' })
    const m = resolving({ state: null })
    // The client's own helper, through the mediator's HTTP handler.
    await pushWebvhLog({ url: 'https://mediator.test' } as never, serializeLog(log), ((input: string | URL | Request, init?: RequestInit) => m.call(new URL(String(input)).pathname, init)) as typeof fetch)
    const reply = await m.request({ did, xKid: `${did}#k_a`, xPriv }, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: did, action: 'add' }] })
    expect((reply.body as any).updated[0].result).toBe('success')
    expect(m.calls.n).toBe(1) // it asked, found no log, and the pushed state stood
  })
})

describe('transport-level errors are standard problem reports', () => {
  const problem = async (res: Response) => {
    expect(res.headers.get('content-type')).toBe('application/didcomm-plain+json')
    return await res.json() as { type: string; pthid?: string; body: { code: string; comment: string; args?: string[] } }
  }

  test('a request that is not an encrypted DIDComm message: 415', async () => {
    const { call } = freshMediator()
    const res = await call('/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })
    expect(res.status).toBe(415)
    const report = await problem(res)
    expect(report.type).toBe('https://didcomm.org/report-problem/2.0/problem-report')
    expect(report.body.code).toBe('e.m.msg')
    expect(report.body.args).toEqual(['application/didcomm-encrypted+json'])
    expect(report.pthid).toBeUndefined() // nothing was readable, so there is no thread
  })

  test('a body that is not a JWE: 400, e.m.msg', async () => {
    const { post } = freshMediator()
    const res = await post({ not: 'a jwe' })
    expect(res.status).toBe(400)
    expect((await problem(res)).body.code).toBe('e.m.msg')
  })

  test('a forward without a next is refused and acknowledged', async () => {
    const { mediator, post } = freshMediator()
    const bad = buildPlaintext('https://didcomm.org/routing/2.0/forward', {})
    bad.attachments = [{ id: 'inner', data: { json: { x: 1 } } }]
    const res = await post(packAnoncrypt(utf8(JSON.stringify(bad)), [{ kid: mediator.xKid, publicKey: mediator.xPub }]))
    expect(res.status).toBe(400)
    const report = await problem(res)
    expect(report.body.code).toBe('e.m.msg')
    expect(report.pthid).toBe(bad.id)
  })

  test('a replayed forward: 400 with the message id as an argument', async () => {
    const { forward, request } = freshMediator()
    const bob = peer()
    await request(bob, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((await forward(bob.did, { n: 1 }, 'same-id')).status).toBe(202)
    const again = await forward(bob.did, { n: 1 }, 'same-id')
    expect(again.status).toBe(400)
    const report = await problem(again)
    expect(report.body.code).toBe('e.m.msg.duplicate')
    expect(report.body.args).toEqual(['same-id'])
  })
})
