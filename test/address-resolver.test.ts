import { describe, expect, test } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { serializeLog } from '../src/protocol/vh/log.ts'
import { resolveDidDocument } from '../src/protocol/did-resolve.ts'
import { buildVhDidCommLog } from './protocol/support/vh-log-fixture.ts'
import { isMailAddress, resolveMailAddressDid } from '../src/client/didcomm/address-resolver.ts'

function fetchFrom(answers: Record<string, unknown>, asked: string[] = []): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = new URL(String(input))
    asked.push(`${url.host} ${url.searchParams.get('resource')}`)
    const answer = answers[url.host]
    if (answer instanceof Error) throw answer
    return answer === undefined ? new Response('Not found', { status: 404 }) : Response.json(answer)
  }) as typeof fetch
}

describe('mail address -> DID (WebFinger)', () => {
  test('the address\'s own domain is asked first, and its DID wins', async () => {
    const asked: string[] = []
    const did = await resolveMailAddressDid('bob@biset.md', ['did.md'], fetchFrom({ 'biset.md': { subject: 'acct:bob@biset.md', aliases: ['https://biset.md/@bob', 'did:web:bob.biset.md'] } }, asked))
    expect(did).toBe('did:web:bob.biset.md')
    expect(asked).toEqual(['biset.md acct:bob@biset.md'])
  })

  test('a domain without a DID for it (no answer, no CORS, no DID alias) falls back to the gateway', async () => {
    const asked: string[] = []
    const did = await resolveMailAddressDid('bob+news@gmail.com', ['did.md'], fetchFrom({
      'gmail.com': new TypeError('Failed to fetch'),
      'did.md': { subject: 'acct:bob+news@gmail.com', aliases: ['did:web:did.md:gmail.com:bob%2Bnews'] },
    }, asked))
    expect(did).toBe('did:web:did.md:gmail.com:bob%2Bnews')
    expect(asked).toEqual(['gmail.com acct:bob+news@gmail.com', 'did.md acct:bob+news@gmail.com'])
    expect(await resolveMailAddressDid('a@x.test', ['did.md'], fetchFrom({ 'x.test': { aliases: ['https://x.test/a'] }, 'did.md': { aliases: ['did:web:did.md:x.test:a'] } }))).toBe('did:web:did.md:x.test:a')
  })

  test('nobody answers: an error that says so', async () => {
    await expect(resolveMailAddressDid('a@x.test', ['did.md'], fetchFrom({}))).rejects.toThrow('No DID answers for a@x.test')
    await expect(resolveMailAddressDid('a@x.test', [], fetchFrom({}))).rejects.toThrow('no mail gateway is configured')
  })

  test('what counts as a mail address', () => {
    expect(isMailAddress('alice@gmail.com')).toBe(true)
    expect(isMailAddress('did:web:did.md:gmail.com:alice')).toBe(false)
    expect(isMailAddress('alice@localhost')).toBe(false)
    expect(isMailAddress('@gmail.com')).toBe(false)
  })
})

describe('a did:vh answer is confirmed by its own log', () => {
  const alice = (() => { const priv = new Uint8Array(32).fill(7); return { priv, pub: ed25519.getPublicKey(priv) } })()
  const { did, log } = buildVhDidCommLog({ rootPrivateKey: alice.priv, rootPublicKey: alice.pub, alsoKnownAs: ['did:web:alice.did.md'] })
  const shadow = { ...JSON.parse(JSON.stringify(log[0]!.state).split(did).join('did:web:alice.did.md')), alsoKnownAs: [did] }

  const world = (overrides: Record<string, () => Response> = {}): typeof fetch => (async (input: string | URL | Request) => {
    const url = String(input)
    const make = overrides[url] ?? ({
      'https://did.md/.well-known/webfinger?resource=acct%3Aalice%40did.md': () => Response.json({ aliases: [did] }),
      'https://alice.did.md/.well-known/did.jsonl': () => new Response(serializeLog(log)),
      'https://alice.did.md/.well-known/did.json': () => Response.json(shadow),
    } as Record<string, () => Response>)[url]
    return make ? make() : new Response('', { status: 404 })
  }) as typeof fetch

  test('alice@did.md is answered with a did:vh whose log names alice.did.md: accepted, and the log is found there afterwards', async () => {
    const found = await resolveMailAddressDid('alice@did.md', [], world())
    expect(found).toBe(did)
    expect((await resolveDidDocument(did, { fetch: world() }))?.id).toBe(did)
  })

  test('refused when the did:web shadow is not what the log derives', async () => {
    await expect(resolveMailAddressDid('alice@did.md', [], world({ 'https://alice.did.md/.well-known/did.json': () => Response.json({ ...shadow, service: [] , extra: true }) }))).rejects.toThrow('does not name alice@did.md')
  })

  test('refused when the log is not at the address\'s host', async () => {
    await expect(resolveMailAddressDid('alice@did.md', [], world({ 'https://alice.did.md/.well-known/did.jsonl': () => new Response('', { status: 404 }) }))).rejects.toThrow('not found at alice.did.md')
  })

  test('refused when the log does not name the address (someone else\'s DID in the answer)', async () => {
    const stranger = buildVhDidCommLog({ rootPrivateKey: alice.priv, rootPublicKey: alice.pub, alsoKnownAs: ['did:web:other.did.md'], versionTime: '2026-08-24T00:00:00Z' })
    await expect(resolveMailAddressDid('alice@did.md', [], world({
      'https://did.md/.well-known/webfinger?resource=acct%3Aalice%40did.md': () => Response.json({ aliases: [stranger.did] }),
      'https://alice.did.md/.well-known/did.jsonl': () => new Response(serializeLog(stranger.log)),
    }))).rejects.toThrow('does not name alice@did.md')
  })
})
