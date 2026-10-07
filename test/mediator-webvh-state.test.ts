// How the mediator reads a did:webvh's keys: webvh-state.ts. The host it
// dials comes from a DID named in a message anyone can send, so the limits
// here are the point.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { serializeLog } from '../src/protocol/webvh/log.ts'
import { createNetworkWebvhResolver, isPublicAddress, isPublicHostname, webvhStateFromLog, WebvhUnavailable } from '../src/server/mediator/webvh-state.ts'
import { buildDidCommLog } from './protocol/support/webvh-log-fixture.ts'

const root = ed25519.utils.randomSecretKey()
const phone = x25519.utils.randomSecretKey()
const { did, log } = buildDidCommLog({
  rootPrivateKey: root, rootPublicKey: ed25519.getPublicKey(root),
  keyAgreementKeys: [{ fragment: 'k_phone', x25519PublicKey: x25519.getPublicKey(phone) }],
  endpointUri: 'https://mediator.example', domain: 'alice.example',
})
const text = serializeLog(log)
const hex = (key: Uint8Array) => [...key].map(x => x.toString(16).padStart(2, '0')).join('')

interface Seen { url: string; init?: RequestInit }
function serving(respond: () => Response | Promise<Response>, seen: Seen[] = []): typeof fetch {
  return (async (input, init) => { seen.push({ url: String(input), init }); return respond() }) as typeof fetch
}

describe('webvhStateFromLog', () => {
  test('reads the DID, its version and every keyAgreement key from a verified log', () => {
    expect(webvhStateFromLog(text)).toEqual({ did, versionNumber: 1, keys: { [`${did}#k_phone`]: hex(x25519.getPublicKey(phone)) } })
  })
  test('refuses a log that does not verify', () => {
    expect(() => webvhStateFromLog(text.replace('alice.example', 'mallory.example'))).toThrow()
    expect(() => webvhStateFromLog('not json')).toThrow()
  })
})

describe('isPublicHostname', () => {
  test('accepts ordinary public names', () => {
    for (const host of ['did.md', 'alice.did.md', 'alice.example', 'sub.domain.example.org']) expect(isPublicHostname(host)).toBe(true)
  })
  test('refuses the host itself, private names and literal addresses', () => {
    for (const host of ['localhost', 'a.localhost', 'nodots', 'printer.local', 'db.internal', 'router.lan', '127.0.0.1', '10.0.0.5', '[::1]', '::1', 'x.test', 'x.invalid']) expect(isPublicHostname(host)).toBe(false)
  })
  test('a trailing dot does not make a private name public', () => {
    for (const host of ['localhost.', 'printer.local.', 'db.internal.', 'a.localhost..', '127.0.0.1.']) expect(isPublicHostname(host)).toBe(false)
    expect(isPublicHostname('did.md.')).toBe(true)
  })
  test('every spelling of an IPv4 address is refused, not just dotted quads', () => {
    for (const host of ['127.1', '2130706433', '0x7f.1', '0x7f000001', '0177.0.0.1', '10.1', '169.254.169.254', '192.168.1', '1.2.3.0x4']) expect(isPublicHostname(host)).toBe(false)
  })
  test('names that merely look like hex or numbers are fine', () => {
    for (const host of ['bad.cafe', 'face.bead.example', '123.example', 'a0x7f.example']) expect(isPublicHostname(host)).toBe(true)
  })
})

const publicLookup = async () => ['93.184.216.34']
const resolverOf = (options: Parameters<typeof createNetworkWebvhResolver>[0]) => createNetworkWebvhResolver({ lookup: publicLookup, ...options })

describe('isPublicAddress', () => {
  test('accepts ordinary public addresses', () => {
    for (const ip of ['93.184.216.34', '8.8.8.8', '1.1.1.1', '2606:2800:220:1:248:1893:25c8:1946', '2001:4860:4860::8888']) expect(isPublicAddress(ip)).toBe(true)
  })
  test('refuses loopback, private, link-local, CGNAT, multicast and reserved ranges', () => {
    for (const ip of ['127.0.0.1', '127.255.0.9', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1']) expect(isPublicAddress(ip)).toBe(false)
    for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1']) expect(isPublicAddress(ip)).toBe(false)
  })
  test('172.15 and 172.32 are public (only 172.16/12 is private)', () => {
    expect(isPublicAddress('172.15.0.1')).toBe(true)
    expect(isPublicAddress('172.32.0.1')).toBe(true)
  })
  test('an IPv4 address inside an IPv6 one is judged as that IPv4 address (mapped, and NAT64)', () => {
    expect(isPublicAddress('::ffff:127.0.0.1')).toBe(false)
    expect(isPublicAddress('::ffff:7f00:1')).toBe(false)
    expect(isPublicAddress('::ffff:93.184.216.34')).toBe(true)
    expect(isPublicAddress('64:ff9b::7f00:1')).toBe(false) // NAT64 of 127.0.0.1
    expect(isPublicAddress('64:ff9b::a00:1')).toBe(false) // NAT64 of 10.0.0.1
    expect(isPublicAddress('64:ff9b::5db8:d822')).toBe(true) // NAT64 of 93.184.216.34
  })
  test('anything that is not an address is refused', () => {
    for (const ip of ['', 'example.com', '999.1.1.1', '1.2.3', 'gggg::1']) expect(isPublicAddress(ip)).toBe(false)
  })
})

describe('createNetworkWebvhResolver', () => {
  test('fetches https, past the CDN, without following redirects', async () => {
    const seen: Seen[] = []
    const state = await resolverOf({ fetch: serving(() => new Response(text), seen) })(did)
    expect(state?.did).toBe(did)
    expect(seen).toHaveLength(1)
    const url = new URL(seen[0]!.url)
    expect(url.origin + url.pathname).toBe('https://alice.example/.well-known/did.jsonl')
    expect(url.searchParams.get('_')).toBeTruthy() // a unique query string: a CDN cannot answer from cache
    expect(seen[0]!.init).toMatchObject({ redirect: 'error', cache: 'no-store' })
    expect(seen[0]!.init?.signal).toBeInstanceOf(AbortSignal)
  })

  test('a DID with no log is null; a failing host or network is "unavailable", not null', async () => {
    expect(await resolverOf({ fetch: serving(() => new Response('', { status: 404 })) })(did)).toBeNull()
    expect(await resolverOf({ fetch: serving(() => new Response('', { status: 410 })) })(did)).toBeNull()
    await expect(resolverOf({ fetch: serving(() => new Response('', { status: 503 })) })(did)).rejects.toThrow(WebvhUnavailable)
    await expect(resolverOf({ fetch: (async () => { throw new Error('connection refused') }) as typeof fetch })(did)).rejects.toThrow(WebvhUnavailable)
  })

  test('a log that does not verify, is too big, or is another DID\'s says nothing about this DID (null)', async () => {
    expect(await resolverOf({ fetch: serving(() => new Response('garbage')) })(did)).toBeNull()
    expect(await resolverOf({ fetch: serving(() => new Response(text)), maxLogBytes: 10 })(did)).toBeNull()
    const other = `did:webvh:${'Q'.repeat(46)}:alice.example`
    expect(await resolverOf({ fetch: serving(() => new Response(text)) })(other)).toBeNull()
  })

  test('never dials a host that is not public, or a port', async () => {
    const seen: Seen[] = []
    const resolver = resolverOf({ fetch: serving(() => new Response(text), seen) })
    const scid = 'Q'.repeat(46)
    for (const host of ['localhost', '127.0.0.1', 'intranet', 'alice.example%3A8443']) expect(await resolver(`did:webvh:${scid}:${host}`)).toBeNull()
    expect(seen).toHaveLength(0)
  })

  test('a private deployment can set its own rule', async () => {
    const seen: Seen[] = []
    await resolverOf({ fetch: serving(() => new Response(text), seen), allowHost: () => true })(did)
    expect(seen).toHaveLength(1)
  })

  test('refuses a public-looking name that resolves to an internal address, and never fetches', async () => {
    for (const address of ['127.0.0.1', '10.0.0.5', '169.254.169.254', '::1', 'fd00::1']) {
      const seen: Seen[] = []
      const resolver = createNetworkWebvhResolver({ fetch: serving(() => new Response(text), seen), lookup: async () => [address] })
      expect(await resolver(did)).toBeNull()
      expect(seen).toHaveLength(0)
    }
  })

  test('every address a name resolves to must be public (one internal address in the answer is enough to refuse)', async () => {
    const seen: Seen[] = []
    const resolver = createNetworkWebvhResolver({ fetch: serving(() => new Response(text), seen), lookup: async () => ['93.184.216.34', '10.0.0.5'] })
    expect(await resolver(did)).toBeNull()
    expect(seen).toHaveLength(0)
  })

  test('a name that does not exist is null; a resolver outage is "unavailable"', async () => {
    const gone = Object.assign(new Error('nx'), { code: 'ENOTFOUND' })
    expect(await createNetworkWebvhResolver({ fetch: serving(() => new Response(text)), lookup: async () => { throw gone } })(did)).toBeNull()
    await expect(createNetworkWebvhResolver({ fetch: serving(() => new Response(text)), lookup: async () => { throw new Error('SERVFAIL') } })(did)).rejects.toThrow(WebvhUnavailable)
  })

  test('the lookup can be turned off for a deployment that cannot reach private networks anyway', async () => {
    const seen: Seen[] = []
    await createNetworkWebvhResolver({ fetch: serving(() => new Response(text), seen), lookup: null })(did)
    expect(seen).toHaveLength(1)
  })
})
