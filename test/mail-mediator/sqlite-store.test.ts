import { expect, test, describe, beforeEach, afterEach } from 'bun:test'
import { Database } from 'bun:sqlite'
import { SqliteMailMediatorStore } from '../../src/mail-mediator/sqlite-store.ts'
import { RouteStoreFullError } from '../../src/mail-mediator/route-store.ts'
import { SpoolFullError } from '../../src/mail-mediator/spool-store.ts'

let store: SqliteMailMediatorStore

beforeEach(() => {
  store = new SqliteMailMediatorStore(new Database(':memory:'))
})

afterEach(() => {
  store.close()
})

describe('SqliteMailMediatorStore', () => {
  test('loadIdentity persists across re-opens against the same database', () => {
    const database = new Database(':memory:')
    const a = new SqliteMailMediatorStore(database)
    const first = a.loadIdentity('https://mail.biset.md')
    const second = new SqliteMailMediatorStore(database).loadIdentity('https://mail.biset.md')
    expect(second.did).toBe(first.did)
    a.close()
  })

  test('loadIdentity throws on a public URL mismatch against a persisted identity', () => {
    const database = new Database(':memory:')
    const a = new SqliteMailMediatorStore(database)
    a.loadIdentity('https://mail.biset.md')
    const b = new SqliteMailMediatorStore(database)
    expect(() => b.loadIdentity('https://other.biset.md')).toThrow()
    a.close()
  })

  test('route bind/lookup/unbind round-trips through SQLite', () => {
    const holder = { relationshipKid: 'did:peer:2.a#key-1', pickupPublicKey: new Uint8Array(32).fill(3), expiresAt: '2030-01-01T00:00:00.000Z' }
    const route = store.bind('y@biset.md', holder, 'gen-1', '2026-01-01T00:00:00.000Z')
    expect(route.holders).toHaveLength(1)
    expect(store.addressForRelationshipKid('did:peer:2.a#key-1')).toBe('y@biset.md')
    const fetched = store.holderFor('y@biset.md', 'did:peer:2.a#key-1')
    expect(fetched?.pickupPublicKey).toEqual(holder.pickupPublicKey)
    expect(store.unbind('y@biset.md', 'did:peer:2.a#key-1')).toBe(true)
    expect(store.routeFor('y@biset.md')).toBeUndefined()
  })

  test('a new route generation revokes prior holders', () => {
    store.bind('y@biset.md', { relationshipKid: 'k1', pickupPublicKey: new Uint8Array(32), expiresAt: '2030-01-01T00:00:00.000Z' }, 'gen-1', '2026-01-01T00:00:00.000Z')
    store.bind('y@biset.md', { relationshipKid: 'k2', pickupPublicKey: new Uint8Array(32), expiresAt: '2030-01-01T00:00:00.000Z' }, 'gen-2', '2026-01-02T00:00:00.000Z')
    expect(store.addressForRelationshipKid('k1')).toBeUndefined()
    expect(store.addressForRelationshipKid('k2')).toBe('y@biset.md')
  })

  test('refuses beyond maxHoldersPerAddress', () => {
    const small = new SqliteMailMediatorStore(new Database(':memory:'), { maxHoldersPerAddress: 1 })
    small.bind('y@biset.md', { relationshipKid: 'k1', pickupPublicKey: new Uint8Array(32), expiresAt: '2030-01-01T00:00:00.000Z' }, 'gen-1', '2026-01-01T00:00:00.000Z')
    expect(() => small.bind('y@biset.md', { relationshipKid: 'k2', pickupPublicKey: new Uint8Array(32), expiresAt: '2030-01-01T00:00:00.000Z' }, 'gen-1', '2026-01-01T00:00:00.000Z'))
      .toThrow(RouteStoreFullError)
    small.close()
  })

  test('spool enqueue is idempotent on semanticIngressId and claim/ack round-trips', () => {
    const input = {
      address: 'y@biset.md', semanticIngressId: 'sid-1', mailFrom: 'sender@example.com',
      encryptedBody: new Uint8Array([1, 2, 3]), bodyHash: new Uint8Array([9, 9]),
      createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-02-01T00:00:00.000Z',
    }
    const first = store.enqueue(input)
    const second = store.enqueue(input)
    expect(second.spoolId).toBe(first.spoolId)
    expect(store.pendingCount('y@biset.md')).toBe(1)

    const claimed = store.claim('y@biset.md', 'holder-a', 60_000, 10, '2026-01-01T00:00:00.000Z')
    expect(claimed).toHaveLength(1)
    expect(claimed[0]!.encryptedBody).toEqual(new Uint8Array([1, 2, 3]))
    const acked = store.acknowledge('y@biset.md', 'holder-a', [claimed[0]!.spoolId])
    expect(acked).toBe(1)
    expect(store.pendingCount('y@biset.md')).toBe(0)
  })

  test('expireLeases rolls an expired claim back to pending', () => {
    store.enqueue({
      address: 'y@biset.md', semanticIngressId: 'sid-1', mailFrom: 'sender@example.com',
      encryptedBody: new Uint8Array([1]), bodyHash: new Uint8Array([1]),
      createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-02-01T00:00:00.000Z',
    })
    store.claim('y@biset.md', 'holder-a', 1000, 10, '2026-01-01T00:00:00.000Z')
    store.expireLeases('2026-01-01T00:00:02.000Z')
    expect(store.pendingCount('y@biset.md')).toBe(1)
  })

  test('refuses beyond maxPendingPerAddress', () => {
    const small = new SqliteMailMediatorStore(new Database(':memory:'), { maxPendingPerAddress: 1 })
    small.enqueue({
      address: 'y@biset.md', semanticIngressId: 'sid-1', mailFrom: 'sender@example.com',
      encryptedBody: new Uint8Array([1]), bodyHash: new Uint8Array([1]),
      createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-02-01T00:00:00.000Z',
    })
    expect(() => small.enqueue({
      address: 'y@biset.md', semanticIngressId: 'sid-2', mailFrom: 'sender@example.com',
      encryptedBody: new Uint8Array([1]), bodyHash: new Uint8Array([1]),
      createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-02-01T00:00:00.000Z',
    })).toThrow(SpoolFullError)
    small.close()
  })

  test('submission acquire/complete round-trips and stays idempotent', () => {
    const first = store.acquire('idem-1', 'y@biset.md', ['a@example.com'], new Uint8Array([1, 2]), '2026-01-01T00:00:00.000Z')
    expect(first.started).toBe(true)
    const retry = store.acquire('idem-1', 'y@biset.md', ['a@example.com'], new Uint8Array([1, 2]), '2026-01-01T00:00:01.000Z')
    expect(retry.started).toBe(false)
    store.complete('idem-1', [{ recipient: 'a@example.com', status: 'accepted' }])
    const record = store.recordFor('idem-1')
    expect(record?.state).toBe('completed')
    expect(record?.results).toEqual([{ recipient: 'a@example.com', status: 'accepted' }])
    expect(record?.rawRfc5322).toEqual(new Uint8Array([1, 2]))
  })

  test('replay guard check() rejects a repeated id within the TTL', () => {
    expect(store.check('msg-1')).toBe(true)
    expect(store.check('msg-1')).toBe(false)
    expect(store.check('MSG-1')).toBe(false) // case-insensitive, mirrors mediator/sqlite-store.ts
  })

  test('ready() reports true for a healthy database', () => {
    expect(store.ready()).toBe(true)
  })

  test('contact history record/hasContact round-trips, is case-insensitive, and scoped per-address', () => {
    expect(store.hasContact('y@biset.md', 'sender@example.com')).toBe(false)
    store.record('y@biset.md', 'Sender@Example.com')
    expect(store.hasContact('y@biset.md', 'sender@example.com')).toBe(true)
    expect(store.hasContact('other@biset.md', 'sender@example.com')).toBe(false)
    expect(() => store.record('y@biset.md', 'sender@example.com')).not.toThrow() // idempotent
  })
})
