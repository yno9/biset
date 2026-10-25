// How the mediator reads a did:vh's keys: a did:vh names no place, so its log is looked for at the operator's watchers
// (GET /log?scid=), with guards on what it dials. The log is dito's shared vector `valid/key-agreement`.
import { describe, expect, test } from 'vitest'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  createVhWatcherResolver, isLogDid, vhStateFromLog, LogUnavailable,
} from '../src/server/mediator/log-state.ts'
import vectors from './fixtures/did-vh-vectors.json'

const file = vectors as unknown as { now: string; vectors: Array<{ name: string; did: string; log: unknown[] }> }
const vector = file.vectors.find(v => v.name === 'valid/key-agreement')!
const did = vector.did
const scid = did.slice('did:vh:'.length)
const text = `${vector.log.map(entry => JSON.stringify(entry)).join('\n')}\n`
const hex = (key: Uint8Array) => [...key].map(x => x.toString(16).padStart(2, '0')).join('')
const agreementHex = hex(sha256(new TextEncoder().encode('did:vh test vector key agreement')))

const publicLookup = async () => ['93.184.216.34']
const serving = (respond: (url: string) => Response | Promise<Response>, seen: string[] = []): typeof fetch =>
  (async input => { seen.push(String(input)); return respond(String(input)) }) as typeof fetch

describe('vhStateFromLog', () => {
  test('reads the DID, its version, its keyAgreement key and its authentication (signing) keys from a verified log', () => {
    const state = vhStateFromLog(text)
    expect(state.did).toBe(did)
    expect(state.versionNumber).toBe(1)
    expect(state.keys).toEqual({ [`${did}#ka`]: agreementHex })
    expect(Object.keys(state.authentication!)).toEqual([`${did}#k`])
  })
  test('refuses a log that does not verify, and a deactivated DID', () => {
    expect(() => vhStateFromLog(text.replace('mediator.example', 'mallory.example'))).toThrow()
    expect(() => vhStateFromLog('not json')).toThrow()
    const deactivated = file.vectors.find(v => v.name === 'valid/deactivated')!
    expect(() => vhStateFromLog(`${deactivated.log.map(entry => JSON.stringify(entry)).join('\n')}\n`)).toThrow(/deactivated/)
  })
})

describe('isLogDid', () => {
  test('a DID whose state is read from a log is a did:vh', () => {
    expect(isLogDid(did)).toBe(true)
    expect(isLogDid('did:peer:2.Ez6')).toBe(false)
    expect(isLogDid('did:web:example.com')).toBe(false)
  })
})

describe('createVhWatcherResolver', () => {
  const resolverOf = (options: Partial<Parameters<typeof createVhWatcherResolver>[0]>) => createVhWatcherResolver({ watchers: ['https://did.md'], lookup: publicLookup, ...options })

  test('asks the watcher for the log by SCID, https, past the CDN, without following redirects', async () => {
    const seen: string[] = []
    let init: RequestInit | undefined
    const fetchImpl = (async (input: RequestInfo | URL, i?: RequestInit) => { seen.push(String(input)); init = i; return new Response(text) }) as typeof fetch
    const state = await resolverOf({ fetch: fetchImpl })(did)
    expect(state?.did).toBe(did)
    expect(state?.keys).toEqual({ [`${did}#ka`]: agreementHex })
    expect(seen).toHaveLength(1)
    expect(seen[0]).toMatch(new RegExp(`^https://did\\.md/log\\?scid=${scid}&_=`))
    expect(init).toMatchObject({ redirect: 'error', cache: 'no-store' })
  })

  test('the first watcher that has the log wins; one without it is skipped; none is "no such DID"', async () => {
    const seen: string[] = []
    const fetchImpl = serving(url => url.startsWith('https://b.example/') ? new Response(text) : new Response('', { status: 404 }), seen)
    expect((await resolverOf({ watchers: ['https://a.example', 'https://b.example'], fetch: fetchImpl })(did))?.did).toBe(did)
    expect(seen.map(url => new URL(url).host)).toEqual(['a.example', 'b.example'])
    expect(await resolverOf({ fetch: serving(() => new Response('', { status: 404 })) })(did)).toBeNull()
    expect(await resolverOf({ watchers: [] })(did)).toBeNull()
  })

  test('a watcher that could not be asked is "retry later", not "no such DID"; another watcher may still answer', async () => {
    await expect(resolverOf({ fetch: serving(() => new Response('', { status: 503 })) })(did)).rejects.toThrow(LogUnavailable)
    await expect(resolverOf({ fetch: (async () => { throw new TypeError('network') }) as typeof fetch })(did)).rejects.toThrow(LogUnavailable)
    const mixed = serving(url => url.startsWith('https://a.example/') ? new Response('', { status: 503 }) : new Response(text))
    expect((await resolverOf({ watchers: ['https://a.example', 'https://b.example'], fetch: mixed })(did))?.did).toBe(did)
    const mixedNotFound = serving(url => url.startsWith('https://a.example/') ? new Response('', { status: 503 }) : new Response('', { status: 404 }))
    await expect(resolverOf({ watchers: ['https://a.example', 'https://b.example'], fetch: mixedNotFound })(did)).rejects.toThrow(LogUnavailable)
  })

  test('a log that does not verify, or is another DID\'s, says nothing about this DID (null); a watcher cannot make up keys', async () => {
    expect(await resolverOf({ fetch: serving(() => new Response(text.replace('mediator.example', 'mallory.example'))) })(did)).toBeNull()
    expect(await resolverOf({ fetch: serving(() => new Response('not json')) })(did)).toBeNull()
    const other = file.vectors.find(v => v.name === 'valid/single-entry')!
    expect(await resolverOf({ fetch: serving(() => new Response(`${other.log.map(entry => JSON.stringify(entry)).join('\n')}\n`)) })(did)).toBeNull()
    expect(await resolverOf({ fetch: serving(() => new Response(text)) })('did:vh:nope')).toBeNull()
    expect(await resolverOf({ fetch: serving(() => new Response(text)) })('did:web:example.com')).toBeNull()
  })

  test('never dials a watcher that is not a public https host, or a port; the answer is bounded', async () => {
    const seen: string[] = []
    const fetchImpl = serving(() => new Response(text), seen)
    for (const watcher of ['http://did.md', 'https://localhost', 'https://127.0.0.1', 'https://did.md:8443', 'ftp://did.md', 'not a url']) {
      expect(await resolverOf({ watchers: [watcher], fetch: fetchImpl })(did), watcher).toBeNull()
    }
    expect(seen).toEqual([])
    expect(await resolverOf({ maxLogBytes: 100, fetch: serving(() => new Response(text, { headers: { 'content-length': String(text.length) } })) })(did)).toBeNull()
    expect(await resolverOf({ lookup: async () => ['10.0.0.1'], fetch: fetchImpl })(did)).toBeNull()
    expect(seen).toEqual([])
  })
})
