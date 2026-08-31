import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { fanOutApplicationMessage } from '../../src/mls-ds/fanout.ts'
import type { ConversationLogEntry } from '../../src/mls-ds/store.ts'

const entry: ConversationLogEntry = { seq: 1, kind: 'application', payload: new Uint8Array([1, 2, 3]), epoch: '0', at: '2026-08-31T00:00:00.000Z' }
// Deterministic, network-free stand-in for "no recipient's DID resolves" --
// what actually happens on the wire is a separate concern from whether
// fanOutApplicationMessage addresses the right kids and shapes its result
// correctly, which is all these tests check.
const notFound: typeof fetch = (async () => new Response('not found', { status: 404 })) as typeof fetch

// resolveWithRouting's resolve() half always uses the real global fetch
// (identity/webvh/resolver.ts's resolve() takes no override -- same note as
// webvh-resolve-sender-key.test.ts) -- only its routing.json half honors
// `opts.fetch`. Both need to be pinned to `notFound` for these tests to be
// network-free and deterministic.
let realFetch: typeof fetch
beforeEach(() => { realFetch = globalThis.fetch; globalThis.fetch = notFound })
afterEach(() => { globalThis.fetch = realFetch })

describe('fanOutApplicationMessage (mls-ds-1.0.md §5.2)', () => {
  test('excludes the sender from the roster it fans out to', async () => {
    const results = await fanOutApplicationMessage('group-1', 'did:web:alice.example#key-1', entry, [
      'did:web:alice.example#key-1', 'did:web:bob.example#key-1', 'did:web:carol.example#key-1',
    ], { fromKid: 'did:web:ds.example#key-1', x25519PrivateKey: new Uint8Array(32), fetch: notFound })
    expect(results.map(r => r.kid)).toEqual(['did:web:bob.example#key-1', 'did:web:carol.example#key-1'])
  })

  test('is best-effort per recipient: an unresolvable recipient DID does not throw or block others', async () => {
    const results = await fanOutApplicationMessage('group-1', 'did:web:alice.example#key-1', entry, [
      'did:web:alice.example#key-1', 'did:web:bob.example#key-1',
    ], { fromKid: 'did:web:ds.example#key-1', x25519PrivateKey: new Uint8Array(32), fetch: notFound })
    expect(results).toHaveLength(1)
    expect(results[0]!.result.ok).toBe(false)
  })

  test('a sole-member group (no one else to notify) resolves to an empty result with no network calls', async () => {
    const results = await fanOutApplicationMessage('group-1', 'did:web:alice.example#key-1', entry, ['did:web:alice.example#key-1'], {
      fromKid: 'did:web:ds.example#key-1', x25519PrivateKey: new Uint8Array(32),
    })
    expect(results).toEqual([])
  })
})
