import { expect, test, describe } from 'bun:test'
import { SpoolStore, SpoolFullError, type EnqueueInput } from '../../src/mail-mediator/spool-store.ts'

function input(overrides: Partial<EnqueueInput> = {}): EnqueueInput {
  return {
    address: 'y@biset.md',
    semanticIngressId: 'sid-1',
    mailFrom: 'sender@example.com',
    encryptedBody: new Uint8Array([1, 2, 3]),
    bodyHash: new Uint8Array([9, 9, 9]),
    createdAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-02-01T00:00:00.000Z',
    ...overrides,
  }
}

describe('SpoolStore', () => {
  test('enqueue is idempotent on semanticIngressId (SMTP retry)', () => {
    const store = new SpoolStore()
    const first = store.enqueue(input())
    const second = store.enqueue(input())
    expect(second.spoolId).toBe(first.spoolId)
    expect(store.pendingCount('y@biset.md')).toBe(1)
  })

  test('claim marks pending records claimed under a lease and stops non-pending records from being claimed again', () => {
    const store = new SpoolStore()
    store.enqueue(input())
    const claimed = store.claim('y@biset.md', 'holder-a', 60_000, 10, '2026-01-01T00:00:00.000Z')
    expect(claimed).toHaveLength(1)
    expect(claimed[0]!.state).toBe('claimed')
    expect(store.pendingCount('y@biset.md')).toBe(0)
    const claimedAgain = store.claim('y@biset.md', 'holder-b', 60_000, 10, '2026-01-01T00:00:01.000Z')
    expect(claimedAgain).toHaveLength(0)
  })

  test('acknowledge by the claiming holder removes the record', () => {
    const store = new SpoolStore()
    store.enqueue(input())
    const [claimed] = store.claim('y@biset.md', 'holder-a', 60_000, 10, '2026-01-01T00:00:00.000Z')
    const acked = store.acknowledge('y@biset.md', 'holder-a', [claimed!.spoolId])
    expect(acked).toBe(1)
    expect(store.claim('y@biset.md', 'holder-a', 60_000, 10, '2026-01-01T00:01:00.000Z')).toHaveLength(0)
  })

  test('acknowledge by a non-claiming holder is refused', () => {
    const store = new SpoolStore()
    store.enqueue(input())
    const [claimed] = store.claim('y@biset.md', 'holder-a', 60_000, 10, '2026-01-01T00:00:00.000Z')
    const acked = store.acknowledge('y@biset.md', 'holder-b', [claimed!.spoolId])
    expect(acked).toBe(0)
  })

  test('expireLeases rolls an expired claim back to pending for another holder', () => {
    const store = new SpoolStore()
    store.enqueue(input())
    store.claim('y@biset.md', 'holder-a', 1000, 10, '2026-01-01T00:00:00.000Z')
    store.expireLeases('2026-01-01T00:00:02.000Z')
    expect(store.pendingCount('y@biset.md')).toBe(1)
    const reclaimed = store.claim('y@biset.md', 'holder-b', 60_000, 10, '2026-01-01T00:00:02.000Z')
    expect(reclaimed).toHaveLength(1)
  })

  test('a late ack from the original holder after reclaim by another holder is refused', () => {
    const store = new SpoolStore()
    store.enqueue(input())
    const [claimed] = store.claim('y@biset.md', 'holder-a', 1000, 10, '2026-01-01T00:00:00.000Z')
    store.expireLeases('2026-01-01T00:00:02.000Z')
    store.claim('y@biset.md', 'holder-b', 60_000, 10, '2026-01-01T00:00:02.000Z')
    const staleAck = store.acknowledge('y@biset.md', 'holder-a', [claimed!.spoolId])
    expect(staleAck).toBe(0)
  })

  test('expireRecords drops records past their own expiresAt regardless of state', () => {
    const store = new SpoolStore()
    store.enqueue(input({ expiresAt: '2026-01-02T00:00:00.000Z' }))
    const dropped = store.expireRecords('2026-06-01T00:00:00.000Z')
    expect(dropped).toBe(1)
    expect(store.pendingCount('y@biset.md')).toBe(0)
  })

  test('refuses beyond MAX_PENDING_PER_ADDRESS', () => {
    const store = new SpoolStore()
    for (let i = 0; i < 10_000; i++) {
      store.enqueue(input({ semanticIngressId: `sid-${i}` }))
    }
    expect(() => store.enqueue(input({ semanticIngressId: 'overflow' }))).toThrow(SpoolFullError)
  })
})
