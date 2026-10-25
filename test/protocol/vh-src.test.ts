// The web location rules of didvh-spec ("Web Locations"), ported from dito's packages/vh/src/src.ts and checked against the same
// cases as dito's tests/vh-src.test.ts, and the did:vh DID URL a recipient may be written as.
import { describe, expect, test } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { logUrlOf, normalizeLocation, parseWebLocation } from '../../src/protocol/vh/src.ts'
import { parseVhDidUrl } from '../../src/protocol/vh/identifier.ts'
import { fetchVhResolution } from '../../src/protocol/vh/fetch.ts'
import { serializeLog } from '../../src/protocol/vh/log.ts'
import { resolveRecipient } from '../../src/client/didcomm/address-resolver.ts'
import { StoredVhPlaces } from '../../src/client/identity/vh-places.ts'
import { configureDidResolution, resolveDidDocument, rememberVhLocation } from '../../src/protocol/did-resolve.ts'
import { buildVhDidCommLog } from '../protocol/support/vh-log-fixture.ts'

describe('web location -> log URL, exactly as didvh-spec lists them', () => {
  test('the specification\'s examples', () => {
    expect(logUrlOf('https://example.com')).toBe('https://example.com/.well-known/did.jsonl')
    expect(logUrlOf('https://example.com/')).toBe('https://example.com/.well-known/did.jsonl')
    expect(logUrlOf('https://example.com/dids/issuer')).toBe('https://example.com/dids/issuer/did.jsonl')
    expect(logUrlOf('https://example.com:3000/dids/issuer')).toBe('https://example.com:3000/dids/issuer/did.jsonl')
    expect(logUrlOf('http://localhost:8000/dids/issuer', { allowLoopback: true })).toBe('http://localhost:8000/dids/issuer/did.jsonl')
    expect(logUrlOf('https://ALICE.did.md')).toBe('https://alice.did.md/.well-known/did.jsonl')
    expect(parseWebLocation('https://bücher.example').host).toBe('xn--bcher-kva.example')
  })

  test('src refuses what a fetcher must not follow', () => {
    const bad = [
      'http://example.com', 'ftp://example.com', 'example.com', '//example.com', 'https://', 'https://user@example.com', 'https://user:pw@example.com',
      'https://example.com?x=1', 'https://example.com/#f', 'https://example.com/a?x', 'https://example.com:0', 'https://example.com:70000',
      'https://127.0.0.1', 'https://10.0.0.1/dids', 'https://[::1]', 'https://[2001:db8::1]', 'https://2130706433', 'https://0x7f.1', 'https://localhost', 'https://intranet',
      'https://example.com/a/../b', 'https://example.com/a/./b', 'https://example.com/%2e%2e/b', 'https://example.com/a%2Fb', 'https://example.com/a%5Cb',
      'https://example.com/a%00b', 'https://example.com/a//b', 'https://example.com/%20a', 'https://example.com/a\\b', 'https://exa mple.com',
    ]
    for (const src of bad) expect(() => parseWebLocation(src), src).toThrow(expect.objectContaining({ name: 'VhResolutionError', code: 'invalidOptions' }))
  })

  test('http is for a loopback host in a local resolver, and only then', () => {
    expect(() => parseWebLocation('http://localhost:8000')).toThrow()
    expect(() => parseWebLocation('http://example.com', { allowLoopback: true })).toThrow()
    expect(() => parseWebLocation('http://10.0.0.1', { allowLoopback: true })).toThrow()
  })

  test('a place is kept normalised: a bare host is the web location https://host; anything invalid is nothing', () => {
    expect(normalizeLocation('Alice.did.md')).toBe('https://alice.did.md')
    expect(normalizeLocation('https://Example.com/dids/issuer/')).toBe('https://example.com/dids/issuer')
    expect(normalizeLocation('127.0.0.1')).toBeUndefined()
    expect(normalizeLocation('https://example.com/a/../b')).toBeUndefined()
  })
})

describe('a did:vh DID URL a recipient is written as', () => {
  const SCID = 'Q'.repeat(46)
  test('the DID with a src (percent-encoded or not) or without one', () => {
    expect(parseVhDidUrl(`did:vh:${SCID}`)).toEqual({ did: `did:vh:${SCID}` })
    expect(parseVhDidUrl(`did:vh:${SCID}?src=https://alice.did.md`)).toEqual({ did: `did:vh:${SCID}`, src: 'https://alice.did.md' })
    expect(parseVhDidUrl(`did:vh:${SCID}?src=${encodeURIComponent('https://example.com/dids/issuer')}`)).toEqual({ did: `did:vh:${SCID}`, src: 'https://example.com/dids/issuer' })
  })

  test('anything else is refused: another parameter, two srcs, a version, a fragment, a path, a src that is not a web location', () => {
    for (const bad of [
      `did:vh:${SCID}?versionId=1-Qm`, `did:vh:${SCID}?src=https://a.example&src=https://b.example`, `did:vh:${SCID}?src=https://a.example&x=1`,
      `did:vh:${SCID}?src=https://a.example#k`, `did:vh:${SCID}/path?src=https://a.example`, `did:vh:${SCID}?src=http://localhost:8000`,
      `did:vh:${SCID}?src=https://127.0.0.1`, `did:vh:${SCID}?src=file:///var/lib/dids`, `did:vh:${SCID}?src=`, `did:vh:short?src=https://a.example`, `did:web:alice.did.md`,
    ]) expect(() => parseVhDidUrl(bad), bad).toThrow()
  })
})

describe('a log published under a path is found at its src', () => {
  const priv = new Uint8Array(32).fill(21)
  const { did, log } = buildVhDidCommLog({ rootPrivateKey: priv, rootPublicKey: ed25519.getPublicKey(priv), alsoKnownAs: [] })
  const served = (asked: string[]) => (async (input: string | URL | Request) => {
    const url = String(input)
    asked.push(url)
    return url === 'https://example.com/dids/issuer/did.jsonl' ? new Response(serializeLog(log)) : new Response('', { status: 404 })
  }) as typeof fetch

  test('the log is read at <src>/did.jsonl, and the location is remembered for the DID', async () => {
    const asked: string[] = []
    expect(await fetchVhResolution(did, { locations: ['https://example.com/dids/issuer'], fetch: served(asked) })).not.toBeNull()
    expect(asked).toEqual(['https://example.com/dids/issuer/did.jsonl'])
  })

  test('resolveRecipient: did:vh:<SCID>?src=… becomes the bare DID, the log must be found there, and a later plain resolve finds it', async () => {
    const asked: string[] = []
    expect(await resolveRecipient(`${did}?src=https://example.com/dids/issuer`, [], served(asked))).toBe(did)
    expect(asked).toEqual(['https://example.com/dids/issuer/did.jsonl'])
    expect((await resolveDidDocument(did, { fetch: served([]) }))?.id).toBe(did) // the place was remembered
    // a src with nothing at it, a bad one, and a recipient written any other way
    await expect(resolveRecipient(`${did}?src=https://nowhere.example`, [], served([]))).rejects.toThrow('log was not found')
    await expect(resolveRecipient(`${did}?src=https://127.0.0.1`, [], served([]))).rejects.toThrow()
    expect(await resolveRecipient(did, [], served([]))).toBe(did)
    expect(await resolveRecipient('did:web:alice.did.md', [], served([]))).toBe('did:web:alice.did.md')
  })

  test('the places a DID was met at survive a reload, a few per DID', () => {
    const data = new Map<string, string>()
    const storage = { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => { data.set(key, value) } }
    const first = new StoredVhPlaces(storage)
    for (const place of ['https://a.example', 'https://b.example', 'https://c.example', 'https://d.example', 'https://e.example']) first.add(did, place)
    expect(new StoredVhPlaces(storage).get(did)).toEqual(['https://b.example', 'https://c.example', 'https://d.example', 'https://e.example'])
    data.set('biset.vh-places', '{not json')
    expect(new StoredVhPlaces(storage).get(did)).toEqual([])
  })

  test('rememberVhLocation ignores what is not a web location', async () => {
    const other = `did:vh:${'R'.repeat(46)}`
    const places = new StoredVhPlaces({ getItem: () => null, setItem: () => {} })
    configureDidResolution({ places })
    rememberVhLocation(other, '127.0.0.1')
    rememberVhLocation(other, 'https://example.com/a/../b')
    rememberVhLocation(other, 'https://example.com/dids/issuer')
    expect(places.get(other)).toEqual(['https://example.com/dids/issuer'])
    configureDidResolution({})
  })
})
