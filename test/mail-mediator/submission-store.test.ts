import { expect, test, describe } from 'bun:test'
import { SubmissionStore } from '../../src/mail-mediator/submission-store.ts'

describe('SubmissionStore', () => {
  test('acquire starts exactly once per idempotency key', () => {
    const store = new SubmissionStore()
    const first = store.acquire('idem-1', 'y@biset.md', ['a@example.com'], new Uint8Array([1]), '2026-01-01T00:00:00.000Z')
    expect(first.started).toBe(true)
    const second = store.acquire('idem-1', 'y@biset.md', ['a@example.com'], new Uint8Array([1]), '2026-01-01T00:00:01.000Z')
    expect(second.started).toBe(false)
    expect(second.record).toBe(first.record)
  })

  test('a retry before complete() sees the in-flight record, not a fresh start', () => {
    const store = new SubmissionStore()
    store.acquire('idem-1', 'y@biset.md', ['a@example.com'], new Uint8Array([1]), '2026-01-01T00:00:00.000Z')
    const retry = store.acquire('idem-1', 'y@biset.md', ['a@example.com'], new Uint8Array([1]), '2026-01-01T00:00:01.000Z')
    expect(retry.started).toBe(false)
    expect(retry.record.state).toBe('in-flight')
  })

  test('complete records per-recipient results and a later retry sees them', () => {
    const store = new SubmissionStore()
    store.acquire('idem-1', 'y@biset.md', ['a@example.com', 'b@example.com'], new Uint8Array([1]), '2026-01-01T00:00:00.000Z')
    store.complete('idem-1', [
      { recipient: 'a@example.com', status: 'accepted' },
      { recipient: 'b@example.com', status: 'temporary-failure', detail: 'greylisted' },
    ])
    const retry = store.acquire('idem-1', 'y@biset.md', ['a@example.com', 'b@example.com'], new Uint8Array([1]), '2026-01-01T00:01:00.000Z')
    expect(retry.started).toBe(false)
    expect(retry.record.state).toBe('completed')
    expect(retry.record.results).toEqual([
      { recipient: 'a@example.com', status: 'accepted' },
      { recipient: 'b@example.com', status: 'temporary-failure', detail: 'greylisted' },
    ])
  })

  test('complete on an unknown key is a no-op returning undefined', () => {
    const store = new SubmissionStore()
    expect(store.complete('missing', [])).toBeUndefined()
  })

  test('recordFor returns undefined for an unknown key', () => {
    const store = new SubmissionStore()
    expect(store.recordFor('missing')).toBeUndefined()
  })
})
