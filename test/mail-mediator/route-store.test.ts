import { expect, test, describe } from 'bun:test'
import { RouteStore, RouteStoreFullError, type RouteHolder } from '../../src/mail-mediator/route-store.ts'

function holder(relationshipKid: string, expiresAt = '2030-01-01T00:00:00.000Z'): RouteHolder {
  return { relationshipKid, pickupPublicKey: new Uint8Array(32).fill(1), expiresAt }
}

describe('RouteStore', () => {
  test('bind creates a route and indexes the holder by relationship kid', () => {
    const store = new RouteStore()
    const route = store.bind('y@biset.md', holder('did:peer:2.a#key-1'), 'gen-1', '2026-01-01T00:00:00.000Z')
    expect(route.address).toBe('y@biset.md')
    expect(route.holders).toHaveLength(1)
    expect(store.addressForRelationshipKid('did:peer:2.a#key-1')).toBe('y@biset.md')
    expect(store.holderFor('y@biset.md', 'did:peer:2.a#key-1')).toBeDefined()
  })

  test('same generation adds a second holder without dropping the first', () => {
    const store = new RouteStore()
    store.bind('y@biset.md', holder('did:peer:2.a#key-1'), 'gen-1', '2026-01-01T00:00:00.000Z')
    const route = store.bind('y@biset.md', holder('did:peer:2.b#key-1'), 'gen-1', '2026-01-01T00:01:00.000Z')
    expect(route.holders).toHaveLength(2)
    expect(store.addressForRelationshipKid('did:peer:2.a#key-1')).toBe('y@biset.md')
    expect(store.addressForRelationshipKid('did:peer:2.b#key-1')).toBe('y@biset.md')
  })

  test('same generation + same relationship kid refreshes in place', () => {
    const store = new RouteStore()
    store.bind('y@biset.md', holder('did:peer:2.a#key-1', '2026-01-01T00:00:00.000Z'), 'gen-1', '2026-01-01T00:00:00.000Z')
    const route = store.bind('y@biset.md', holder('did:peer:2.a#key-1', '2027-01-01T00:00:00.000Z'), 'gen-1', '2026-01-02T00:00:00.000Z')
    expect(route.holders).toHaveLength(1)
    expect(route.holders[0]!.expiresAt).toBe('2027-01-01T00:00:00.000Z')
  })

  test('a new generation revokes every prior holder outright', () => {
    const store = new RouteStore()
    store.bind('y@biset.md', holder('did:peer:2.a#key-1'), 'gen-1', '2026-01-01T00:00:00.000Z')
    store.bind('y@biset.md', holder('did:peer:2.b#key-1'), 'gen-1', '2026-01-01T00:01:00.000Z')
    const route = store.bind('y@biset.md', holder('did:peer:2.c#key-1'), 'gen-2', '2026-02-01T00:00:00.000Z')
    expect(route.holders).toHaveLength(1)
    expect(route.holders[0]!.relationshipKid).toBe('did:peer:2.c#key-1')
    expect(store.addressForRelationshipKid('did:peer:2.a#key-1')).toBeUndefined()
    expect(store.addressForRelationshipKid('did:peer:2.b#key-1')).toBeUndefined()
    expect(store.addressForRelationshipKid('did:peer:2.c#key-1')).toBe('y@biset.md')
  })

  test('unbind removes exactly one holder and drops the address once empty', () => {
    const store = new RouteStore()
    store.bind('y@biset.md', holder('did:peer:2.a#key-1'), 'gen-1', '2026-01-01T00:00:00.000Z')
    expect(store.unbind('y@biset.md', 'did:peer:2.a#key-1')).toBe(true)
    expect(store.routeFor('y@biset.md')).toBeUndefined()
    expect(store.unbind('y@biset.md', 'did:peer:2.a#key-1')).toBe(false)
  })

  test('expireHolders drops only holders past their own expiresAt', () => {
    const store = new RouteStore()
    store.bind('y@biset.md', holder('did:peer:2.a#key-1', '2026-01-01T00:00:00.000Z'), 'gen-1', '2025-12-01T00:00:00.000Z')
    store.bind('y@biset.md', holder('did:peer:2.b#key-1', '2030-01-01T00:00:00.000Z'), 'gen-1', '2025-12-01T00:00:01.000Z')
    store.expireHolders('2026-06-01T00:00:00.000Z')
    const route = store.routeFor('y@biset.md')
    expect(route?.holders).toHaveLength(1)
    expect(route?.holders[0]!.relationshipKid).toBe('did:peer:2.b#key-1')
    expect(store.addressForRelationshipKid('did:peer:2.a#key-1')).toBeUndefined()
  })

  test('expireHolders drops the address entirely once every holder is gone', () => {
    const store = new RouteStore()
    store.bind('y@biset.md', holder('did:peer:2.a#key-1', '2026-01-01T00:00:00.000Z'), 'gen-1', '2025-12-01T00:00:00.000Z')
    store.expireHolders('2026-06-01T00:00:00.000Z')
    expect(store.routeFor('y@biset.md')).toBeUndefined()
  })

  test('refuses beyond MAX_HOLDERS_PER_ADDRESS within one generation', () => {
    const store = new RouteStore()
    for (let i = 0; i < 8; i++) {
      store.bind('y@biset.md', holder(`did:peer:2.${i}#key-1`), 'gen-1', '2026-01-01T00:00:00.000Z')
    }
    expect(() => store.bind('y@biset.md', holder('did:peer:2.overflow#key-1'), 'gen-1', '2026-01-01T00:00:00.000Z'))
      .toThrow(RouteStoreFullError)
  })
})
