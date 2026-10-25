// A did:web is only the first rung: once it leads to a did:vh that confirms it, only the did:vh is believed (resolveTrustedDid).
import { describe, expect, test } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { resolveTrustedDid, type DidLinks } from '../src/protocol/did-resolve.ts'
import { serializeLog } from '../src/protocol/vh/log.ts'
import { buildGenesisLog } from './protocol/support/did-log-fixture.ts'
import { extendVhLog } from './protocol/support/vh-log-fixture.ts'

const WEB = 'did:web:alice.did.md'
const priv = new Uint8Array(32).fill(5)
const pub = ed25519.getPublicKey(priv)
const { did, log } = buildGenesisLog(priv, pub, [], 'alice.did.md')
const shadowOf = (state: object, vhDid: string, alsoKnownAs = [`${vhDid}?src=https://alice.did.md`]) =>
  ({ ...JSON.parse(JSON.stringify(state).split(vhDid).join(WEB)), alsoKnownAs })
const shadow = shadowOf(log[0]!.state, did)

function links(): DidLinks & { map: Map<string, string> } {
  const map = new Map<string, string>()
  return { map, get: web => map.get(web), set: (web, vh) => { map.set(web, vh) } }
}
function world(parts: { web?: unknown; log?: unknown[]; asked?: string[] }): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input).split('?')[0]
    parts.asked?.push(url!)
    if (url === 'https://alice.did.md/.well-known/did.json') return parts.web === undefined ? new Response('', { status: 404 }) : Response.json(parts.web)
    if (url === 'https://alice.did.md/.well-known/did.jsonl') return parts.log === undefined ? new Response('', { status: 404 }) : new Response(serializeLog(parts.log as never))
    return new Response('', { status: 404 })
  }) as typeof fetch
}

describe('resolveTrustedDid', () => {
  test('a did:web that points to no did:vh is believed as it is (a mail bridge, a mediator)', async () => {
    const plain = { id: WEB, service: [] }
    const trusted = await resolveTrustedDid(WEB, { fetch: world({ web: plain }), links: links() })
    expect(trusted).toMatchObject({ did: WEB, linked: false })
    expect(await resolveTrustedDid(WEB, { fetch: world({}), links: links() })).toBeNull()
  })

  test('a did:web that points to a did:vh which confirms it leads to the did:vh, and is remembered', async () => {
    const memory = links()
    const trusted = await resolveTrustedDid(WEB, { fetch: world({ web: shadow, log }), links: memory })
    expect(trusted).toMatchObject({ did, linked: true })
    expect((trusted!.document as { id: string }).id).toBe(did)
    expect(memory.map.get(WEB)).toBe(did)
  })

  test('refused, not believed as a did:web, when the did:vh does not confirm it', async () => {
    const memory = links()
    // the did:web document is not what the log derives
    const tampered = { ...shadow, service: [{ id: `${WEB}#x`, type: 'DIDCommMessaging', serviceEndpoint: 'https://mallory.example' }] }
    await expect(resolveTrustedDid(WEB, { fetch: world({ web: tampered, log }), links: memory })).rejects.toThrow(/does not confirm it/)
    // the log does not name this did:web
    const other = buildGenesisLog(priv, pub, [], 'bob.did.md')
    const lying = shadowOf(other.log[0]!.state, other.did, [`${other.did}?src=https://alice.did.md`])
    await expect(resolveTrustedDid(WEB, { fetch: world({ web: { ...lying, id: WEB }, log: other.log }), links: memory })).rejects.toThrow()
    // the log is nowhere
    await expect(resolveTrustedDid(WEB, { fetch: world({ web: shadow }), links: memory })).rejects.toThrow(/log was not found/)
    expect(memory.map.size).toBe(0)
  })

  test('two different did:vh in one did:web are refused', async () => {
    const other = buildGenesisLog(new Uint8Array(32).fill(6), ed25519.getPublicKey(new Uint8Array(32).fill(6)), [], 'alice.did.md')
    const both = { ...shadow, alsoKnownAs: [`${did}?src=https://alice.did.md`, other.did] }
    await expect(resolveTrustedDid(WEB, { fetch: world({ web: both, log }), links: links() })).rejects.toThrow(/more than one did:vh/)
  })

  test('once remembered, the did:web is never asked again, and the did:vh may stop naming it', async () => {
    const memory = links()
    await resolveTrustedDid(WEB, { fetch: world({ web: shadow, log }), links: memory })
    const asked: string[] = []
    // the did:web host now says something else, and the did:vh dropped the did:web alias: the relationship goes on
    const dropped = extendVhLog(log, priv, pub, state => { (state as { alsoKnownAs: string[] }).alsoKnownAs = [] }, '2026-08-24T00:00:00Z')
    const trusted = await resolveTrustedDid(WEB, { fetch: world({ web: { id: WEB, service: [] }, log: dropped, asked }), links: memory })
    expect(trusted).toMatchObject({ did, linked: true })
    expect(asked.some(url => url.endsWith('/did.json'))).toBe(false)
  })

  test('a did:vh is its own answer', async () => {
    expect(await resolveTrustedDid(did, { fetch: world({ log }), links: links() })).toMatchObject({ did, linked: false })
  })
})
