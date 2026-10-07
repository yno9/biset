import { describe, expect, test } from 'bun:test'
import { queuedMessageOf } from '../src/protocol/didcomm/mediator-pickup.ts'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { QueueFullError, SqliteMediatorStore } from '../src/server/mediator/sqlite-store.ts'
import { IpRateLimiter } from '../src/server/mediator/rate-limit.ts'
import { deviceLabel, freshMediator, peer, T } from './support/mediator.ts'

function withDatabase<T>(run: (path: string) => Promise<T> | T): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'biset-mediator-sqlite-test-'))
  return Promise.resolve(run(join(dir, 'mediator.sqlite'))).finally(() => rmSync(dir, { recursive: true, force: true }))
}

describe('SqliteMediatorStore', () => {
  test('an accepted Forward survives restart, its replay id too, and an ACK stays durable', () => withDatabase(async path => {
    const bob = peer()
    const device = deviceLabel(1)
    const first = freshMediator({}, SqliteMediatorStore.open(path))
    await first.request(bob, T.RECIPIENT_UPDATE, { device, updates: [{ recipient_did: bob.did, action: 'add' }] })
    expect((await first.forward(bob.xKid, { ciphertext: 'opaque-inner-jwe' }, 'durable-forward-id')).status).toBe(202)
    first.store.close()

    const second = freshMediator({}, SqliteMediatorStore.open(path))
    expect((await second.forward(bob.xKid, { ciphertext: 'opaque-inner-jwe' }, 'durable-forward-id')).status).toBe(400)
    const delivery = await second.request(bob, T.DELIVERY_REQUEST, { device })
    expect(delivery.attachments).toHaveLength(1)
    expect(queuedMessageOf(delivery.attachments![0]!)).toEqual({ ciphertext: 'opaque-inner-jwe' })
    const ack = await second.request(bob, T.MESSAGES_RECEIVED, { device, message_id_list: [delivery.attachments![0]!.id] })
    expect((ack.body as { message_count: number }).message_count).toBe(0)
    second.store.close()

    const third = SqliteMediatorStore.open(path)
    expect(third.count(bob.did, device)).toBe(0)
    expect(third.stats().queuedMessages).toBe(0)
    third.close()
  }))

  test('relay poller identity is stable across restarts and independent of the mediator\'s own identity', () => withDatabase(path => {
    const first = SqliteMediatorStore.open(path)
    const ownIdentity = first.loadIdentity('https://mediator.example')
    const pollerIdentity = first.loadRelayPollerIdentity()
    expect(pollerIdentity.did).not.toBe(ownIdentity.did)
    first.close()

    const second = SqliteMediatorStore.open(path)
    expect(second.loadRelayPollerIdentity().did).toBe(pollerIdentity.did)
    second.close()
  }))

  test('mail plugin identity is stable across restarts and independent of the mediator\'s and relay poller\'s own identities', () => withDatabase(path => {
    const first = SqliteMediatorStore.open(path)
    const ownIdentity = first.loadIdentity('https://mediator.example')
    const pollerIdentity = first.loadRelayPollerIdentity()
    const mailPluginIdentity = first.loadMailPluginIdentity()
    expect(new Set([ownIdentity.did, pollerIdentity.did, mailPluginIdentity.did]).size).toBe(3)
    first.close()

    const second = SqliteMediatorStore.open(path)
    expect(second.loadMailPluginIdentity().did).toBe(mailPluginIdentity.did)
    second.close()
  }))

  test('mediator identity, inboxes, did:webvh state, opaque queue, and replay IDs survive restart', () => withDatabase(path => {
    const did = 'did:webvh:scid:example.test'
    const first = SqliteMediatorStore.open(path)
    const identity = first.loadIdentity('https://mediator.example')
    first.recordWebvhState(did, 3, { [`${did}#k_a`]: '010203' })
    expect(first.addInbox(did, deviceLabel(1), `${did}#k_a`)).toBe('added')
    expect(first.enqueue(did, JSON.stringify({ ciphertext: 'opaque' }))).toBe(1)
    expect(first.check('Message-ID-A')).toBe(true)
    first.close()

    const second = SqliteMediatorStore.open(path)
    expect(second.loadIdentity('https://mediator.example').did).toBe(identity.did)
    expect(second.listInboxes(did).map(inbox => inbox.device)).toEqual([deviceLabel(1)])
    expect(second.webvhKey(did, `${did}#k_a`)).toBe('010203')
    expect(second.peek(did, deviceLabel(1), 10)).toEqual([expect.objectContaining({ packed: JSON.stringify({ ciphertext: 'opaque' }) })])
    expect(second.check('message-id-a')).toBe(false)
    second.close()
  }))

  test('queue quota failure rolls back a replay ID in the shared Forward transaction', () => withDatabase(path => {
    const store = SqliteMediatorStore.open(path, { maxQueueItemsPerInbox: 1, maxQueueBytesPerInbox: 64, maxMessageBytes: 64 })
    const did = 'did:peer:2.bob'
    store.addInbox(did, deviceLabel(1), `${did}#key-1`)
    store.enqueue(did, '{}')
    expect(() => store.transaction(() => {
      expect(store.check('forward-retry')).toBe(true)
      store.enqueue(did, '{}')
    })).toThrow(QueueFullError)
    // The failed transaction did not poison the retry as a replay.
    expect(store.check('forward-retry')).toBe(true)
    store.close()
  }))

  test('ACK removal is idempotent and remains removed after restart', () => withDatabase(path => {
    const did = 'did:peer:2.carol'
    const first = SqliteMediatorStore.open(path)
    first.addInbox(did, deviceLabel(1), `${did}#key-1`)
    first.enqueue(did, '{"ciphertext":"x"}')
    const [message] = first.peek(did, deviceLabel(1), 10)
    expect(first.acknowledge(did, deviceLabel(1), [message!.id])).toBe(0)
    expect(first.acknowledge(did, deviceLabel(1), [message!.id])).toBe(0)
    first.close()

    const second = SqliteMediatorStore.open(path)
    expect(second.count(did, deviceLabel(1))).toBe(0)
    second.close()
  }))

  test('messages past the queue TTL are dropped from every inbox', () => {
    const store = SqliteMediatorStore.memory({ queueTtlMs: 60_000 })
    const did = 'did:peer:2.dave'
    const now = Date.now()
    store.addInbox(did, deviceLabel(1), `${did}#key-1`, now)
    store.addInbox(did, deviceLabel(2), `${did}#key-1`, now)
    store.enqueue(did, '{}', now - 120_000)
    store.expire(now)
    expect(store.stats()).toMatchObject({ queuedMessages: 0, pendingDeliveries: 0 })
  })

  test('persisted public URL cannot change silently', () => withDatabase(path => {
    const first = SqliteMediatorStore.open(path)
    first.loadIdentity('https://mediator.example')
    first.close()
    const second = SqliteMediatorStore.open(path)
    expect(() => second.loadIdentity('https://other.example')).toThrow('MEDIATOR_PUBLIC_URL differs')
    second.close()
  }))

  test('a corrupt database fails startup instead of becoming an empty mediator', () => withDatabase(path => {
    writeFileSync(path, 'not a sqlite database')
    expect(() => SqliteMediatorStore.open(path)).toThrow()
  }))
})

describe('IpRateLimiter', () => {
  test('bounds one transport address without coupling different addresses', () => {
    const limiter = new IpRateLimiter(2, 1000)
    expect(limiter.allow('192.0.2.1', 0)).toBe(true)
    expect(limiter.allow('192.0.2.1', 1)).toBe(true)
    expect(limiter.allow('192.0.2.1', 2)).toBe(false)
    expect(limiter.allow('192.0.2.2', 2)).toBe(true)
    expect(limiter.allow('192.0.2.1', 1000)).toBe(true)
  })
})
