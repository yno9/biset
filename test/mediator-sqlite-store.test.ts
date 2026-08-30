import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SqliteMediatorStore } from '../src/mediator/sqlite-store.ts'
import { QueueFullError } from '../src/mediator/queue.ts'
import { createMediator } from '../src/mediator/server.ts'
import { generatePeerIdentity } from '../src/didcomm/peer.ts'
import { buildPlaintext, type DidCommPlaintext } from '../src/didcomm/message.ts'
import { packAnoncrypt, packAuthcrypt, parseJwe, unpackAuthcrypt } from '../src/didcomm/crypto.ts'
import { DELIVERY_REQUEST, MESSAGES_RECEIVED } from '../src/didcomm/mediator-protocol.ts'
import { IpRateLimiter } from '../src/mediator/rate-limit.ts'

function withDatabase<T>(run: (path: string) => Promise<T> | T): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'biset-mediator-sqlite-test-'))
  return Promise.resolve(run(join(dir, 'mediator.sqlite'))).finally(() => rmSync(dir, { recursive: true, force: true }))
}

describe('SqliteMediatorStore', () => {
  test('accepted Forward survives process restart, wire pickup works, and ACK remains durable', () => withDatabase(async path => {
    const bob = generatePeerIdentity()
    let first = SqliteMediatorStore.open(path)
    let mediator = first.loadIdentity('https://mediator.example')
    first.addKey(bob.did, bob.xKid, bob.xKid, hex(bob.xPub))
    let handler = createMediator({
      mediator, queue: first, connections: first, replay: first, transaction: first.transaction,
    }).handle

    const forward = buildPlaintext('https://didcomm.org/routing/2.0/forward', { next: bob.xKid })
    forward.id = 'durable-forward-id'
    forward.attachments = [{ id: 'inner', data: { json: { ciphertext: 'opaque-inner-jwe' } } }]
    const packedForward = packAnoncrypt(bytes(JSON.stringify(forward)), { kid: mediator.xKid, publicKey: mediator.xPub })
    expect((await post(handler, packedForward)).status).toBe(202)
    first.close()

    const second = SqliteMediatorStore.open(path)
    mediator = second.loadIdentity('https://mediator.example')
    handler = createMediator({
      mediator, queue: second, connections: second, replay: second, transaction: second.transaction,
    }).handle
    expect((await post(handler, packedForward)).status).toBe(400)

    const delivery = await authenticatedRequest(handler, mediator, bob, DELIVERY_REQUEST, { recipient_did: bob.xKid })
    expect(delivery.attachments).toHaveLength(1)
    expect(delivery.attachments![0]!.data.json).toEqual({ ciphertext: 'opaque-inner-jwe' })
    const ackId = delivery.attachments![0]!.id
    const ack = await authenticatedRequest(handler, mediator, bob, MESSAGES_RECEIVED, { message_id_list: [ackId] })
    expect((ack.body as { message_count: number }).message_count).toBe(0)
    second.close()

    const third = SqliteMediatorStore.open(path)
    expect(third.count(bob.xKid)).toBe(0)
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

  test('mediator identity, connection keylist, opaque queue, and replay IDs survive restart', () => withDatabase(path => {
    const first = SqliteMediatorStore.open(path)
    const identity = first.loadIdentity('https://mediator.example')
    first.register('did:peer:alice')
    expect(first.addKey('did:peer:alice', 'did:peer:alice#key-1', 'did:peer:alice', '010203')).toBe(true)
    const queueId = first.push('did:peer:alice#key-1', JSON.stringify({ ciphertext: 'opaque' }))
    expect(first.check('Message-ID-A')).toBe(true)
    first.close()

    const second = SqliteMediatorStore.open(path)
    expect(second.loadIdentity('https://mediator.example').did).toBe(identity.did)
    expect(second.listKeys('did:peer:alice')).toEqual(['did:peer:alice#key-1'])
    expect(second.keyFor('did:peer:alice#key-1')).toBe('010203')
    expect(second.peek('did:peer:alice#key-1', 10)).toEqual([expect.objectContaining({
      id: queueId,
      packed: JSON.stringify({ ciphertext: 'opaque' }),
    })])
    expect(second.check('message-id-a')).toBe(false)
    second.close()
  }))

  test('queue quota failure rolls back a replay ID in the shared Forward transaction', () => withDatabase(path => {
    const store = SqliteMediatorStore.open(path, {
      maxQueueItemsPerRecipient: 1,
      maxQueueBytesPerRecipient: 64,
      maxMessageBytes: 64,
    })
    const kid = 'did:peer:bob#key-1'
    store.addKey('did:peer:bob', kid)
    store.push(kid, '{}')

    expect(() => store.transaction(() => {
      expect(store.check('forward-retry')).toBe(true)
      store.push(kid, '{}')
    })).toThrow(QueueFullError)

    // The failed transaction did not poison the retry as a replay.
    expect(store.check('forward-retry')).toBe(true)
    store.close()
  }))

  test('ACK removal is idempotent and remains removed after restart', () => withDatabase(path => {
    const first = SqliteMediatorStore.open(path)
    const kid = 'did:peer:carol#key-1'
    first.addKey('did:peer:carol', kid)
    const id = first.push(kid, '{"ciphertext":"x"}')
    expect(first.remove(kid, [id])).toBe(0)
    expect(first.remove(kid, [id])).toBe(0)
    first.close()

    const second = SqliteMediatorStore.open(path)
    expect(second.count(kid)).toBe(0)
    second.close()
  }))

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

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value)
const hex = (value: Uint8Array): string => [...value].map(byte => byte.toString(16).padStart(2, '0')).join('')

async function post(handler: ReturnType<typeof createMediator>['handle'], body: unknown): Promise<Response> {
  const url = new URL('https://mediator.example/')
  const response = await handler(new Request(url, { method: 'POST', body: JSON.stringify(body) }), url)
  if (!response) throw new Error('mediator did not handle POST /')
  return response
}

async function authenticatedRequest(
  handler: ReturnType<typeof createMediator>['handle'],
  mediator: ReturnType<typeof generatePeerIdentity>,
  sender: ReturnType<typeof generatePeerIdentity>,
  type: string,
  body: unknown,
): Promise<DidCommPlaintext> {
  const plaintext = buildPlaintext(type, body, sender.did, mediator.did)
  const packed = packAuthcrypt(
    bytes(JSON.stringify(plaintext)),
    { kid: sender.xKid, privateKey: sender.xPriv },
    { kid: mediator.xKid, publicKey: mediator.xPub },
  )
  const response = await post(handler, packed)
  expect(response.status).toBe(200)
  const reply = parseJwe(await response.json())
  if (!reply) throw new Error('mediator reply is not a JWE')
  const unpacked = await unpackAuthcrypt(reply, { kid: sender.xKid, privateKey: sender.xPriv }, async () => mediator.xPub)
  return JSON.parse(new TextDecoder().decode(unpacked.plaintext)) as DidCommPlaintext
}
