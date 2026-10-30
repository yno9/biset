// resolveDidDocument: one way to resolve a DID of any method; a did:vh's log is looked for at the places the caller knows.
import { afterEach, expect, test } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { serializeLog } from '../../src/protocol/vh/log.ts'
import { configureDidResolution, resolveDidDocument } from '../../src/protocol/did-resolve.ts'
import { StaleLogError, InMemoryVersionMemory } from '../../src/protocol/freshness.ts'
import { buildVhDidCommLog, extendVhLog } from './support/vh-log-fixture.ts'

const key = (seed: number) => { const priv = new Uint8Array(32).fill(seed); return { priv, pub: ed25519.getPublicKey(priv) } }
const alice = key(7)
const mine = buildVhDidCommLog({ rootPrivateKey: alice.priv, rootPublicKey: alice.pub, endpointUri: 'https://m.example/didcomm', alsoKnownAs: ['did:web:alice.did.md'] })
const other = buildVhDidCommLog({ rootPrivateKey: key(9).priv, rootPublicKey: key(9).pub })

const serving = (files: Record<string, string>, seen: string[] = []): typeof fetch =>
  (async input => {
    seen.push(String(input))
    const body = files[String(input)]
    return body === undefined ? new Response('', { status: 404 }) : new Response(body)
  }) as typeof fetch

afterEach(() => configureDidResolution({}))

test('a did:vh is found at a host the contact is known by', async () => {
  const doc = await resolveDidDocument(mine.did, { fetch: serving({ 'https://alice.did.md/.well-known/did.jsonl': serializeLog(mine.log) }), vh: { locations: ['alice.did.md'] } })
  expect(doc?.id).toBe(mine.did)
})

test('or at a watcher, by SCID', async () => {
  const scid = mine.did.slice('did:vh:'.length)
  const doc = await resolveDidDocument(mine.did, { fetch: serving({ [`https://w.example/log?scid=${scid}`]: serializeLog(mine.log) }), vh: { watchers: ['https://w.example'] } })
  expect(doc?.id).toBe(mine.did)
})

test('a copy that is another identity\'s is passed over, and the next place is asked', async () => {
  const seen: string[] = []
  const doc = await resolveDidDocument(mine.did, {
    fetch: serving({ 'https://liar.example/.well-known/did.jsonl': serializeLog(other.log), 'https://alice.did.md/.well-known/did.jsonl': serializeLog(mine.log) }, seen),
    vh: { locations: ['liar.example', 'alice.did.md'] },
  })
  expect(doc?.id).toBe(mine.did)
  expect(seen).toHaveLength(2)
})

test('nobody has it: null, not an error', async () => {
  expect(await resolveDidDocument(mine.did, { fetch: serving({}), vh: { locations: ['alice.did.md'] } })).toBeNull()
})

test('the places configured for the app are asked too, and a memory refuses an old copy served later', async () => {
  const newer = extendVhLog(mine.log, alice.priv, alice.pub, state => { state.alsoKnownAs = ['did:web:alice.did.md', 'did:web:alice2.did.md'] }, '2026-08-24T00:00:00Z')
  const memory = new InMemoryVersionMemory()
  configureDidResolution({ locationsOf: () => ['alice.did.md'], memory })
  const url = 'https://alice.did.md/.well-known/did.jsonl'
  await resolveDidDocument(mine.did, { fetch: serving({ [url]: serializeLog(newer) }) })
  await expect(resolveDidDocument(mine.did, { fetch: serving({ [url]: serializeLog(mine.log) }) })).rejects.toThrow(StaleLogError)
})

test('a place the identity has left, still serving its old log, does not stop the search: the next place has the current one', async () => {
  const newer = extendVhLog(mine.log, alice.priv, alice.pub, state => { state.alsoKnownAs = ['did:web:alice2.did.md'] }, '2026-08-24T00:00:00Z')
  const memory = new InMemoryVersionMemory()
  const old = 'https://alice.did.md/.well-known/did.jsonl'
  const current = 'https://alice2.did.md/.well-known/did.jsonl'
  await resolveDidDocument(mine.did, { fetch: serving({ [current]: serializeLog(newer) }), vh: { locations: ['alice2.did.md'] }, memory })
  const doc = await resolveDidDocument(mine.did, { fetch: serving({ [old]: serializeLog(mine.log), [current]: serializeLog(newer) }), vh: { locations: ['alice.did.md', 'alice2.did.md'] }, memory })
  expect(doc?.alsoKnownAs).toEqual(['did:web:alice2.did.md'])
})
