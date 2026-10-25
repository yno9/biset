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
    expect(asked[0]).toBe('biset.md acct:bob@biset.md') // then the did:web document it names is followed (a plain did:web here: it is not found)
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

describe('the domain answers with the identity\'s did:web, and the ladder leads on to the did:vh', () => {
  const alice = (() => { const priv = new Uint8Array(32).fill(7); return { priv, pub: ed25519.getPublicKey(priv) } })()
  const { did, log } = buildVhDidCommLog({ rootPrivateKey: alice.priv, rootPublicKey: alice.pub, alsoKnownAs: ['did:web:alice.did.md'] })
  const shadow = { ...JSON.parse(JSON.stringify(log[0]!.state).split(did).join('did:web:alice.did.md')), alsoKnownAs: [`${did}?src=https://alice.did.md`] }

  const world = (asked: string[], overrides: Record<string, () => Response> = {}): typeof fetch => (async (input: string | URL | Request) => {
    const url = String(input)
    asked.push(url.replace(/\?_=.*/, ''))
    const make = overrides[url] ?? ({
      'https://did.md/.well-known/webfinger?resource=acct%3Aalice%40did.md': () => Response.json({ subject: 'acct:alice@did.md', aliases: ['did:web:alice.did.md'] }),
      'https://alice.did.md/.well-known/did.json': () => Response.json(shadow),
      'https://alice.did.md/.well-known/did.jsonl': () => new Response(serializeLog(log)),
    } as Record<string, () => Response>)[url]
    return make ? make() : new Response('', { status: 404 })
  }) as typeof fetch

  test('alice@did.md: WebFinger, then the did:web document, then the log it points to; no bridge, no guessing of a host', async () => {
    const asked: string[] = []
    expect(await resolveMailAddressDid('alice@did.md', ['did.md'], world(asked))).toBe(did)
    expect(asked).toEqual([
      'https://did.md/.well-known/webfinger?resource=acct%3Aalice%40did.md',
      'https://alice.did.md/.well-known/did.json',
      'https://alice.did.md/.well-known/did.jsonl',
    ])
  })

  test('refused, not trusted as a did:web, when the did:web document is not what the log derives', async () => {
    await expect(resolveMailAddressDid('alice@did.md', [], world([], { 'https://alice.did.md/.well-known/did.json': () => Response.json({ ...shadow, service: [], extra: true }) }))).rejects.toThrow('does not confirm it')
  })

  test('refused when the log it points to is nowhere', async () => {
    await expect(resolveMailAddressDid('alice@did.md', [], world([], { 'https://alice.did.md/.well-known/did.jsonl': () => new Response('', { status: 404 }) }))).rejects.toThrow('log was not found')
  })

  test('a did:web that points to no did:vh is a plain did:web contact; one that cannot be reached now is kept as it is', async () => {
    expect(await resolveMailAddressDid('alice@did.md', [], world([], { 'https://alice.did.md/.well-known/did.json': () => Response.json({ id: 'did:web:alice.did.md', service: [] }) }))).toBe('did:web:alice.did.md')
    expect(await resolveMailAddressDid('alice@did.md', [], world([], { 'https://alice.did.md/.well-known/did.json': () => new Response('', { status: 503 }) }))).toBe('did:web:alice.did.md')
  })

  test('a domain that answers with a did:vh and the place of its log (?src=) is believed once the log is found and verifies', async () => {
    const answer = (src: string) => ({ 'https://example.org/.well-known/webfinger?resource=acct%3Aalice%40example.org': () => Response.json({ aliases: [`${did}?src=${src}`] }), 'https://elsewhere.example/.well-known/did.jsonl': () => new Response(serializeLog(log)) })
    expect(await resolveMailAddressDid('alice@example.org', [], world([], answer('https://elsewhere.example')))).toBe(did)
    await expect(resolveMailAddressDid('alice@example.org', [], world([], { ...answer('https://nowhere.example'), 'https://elsewhere.example/.well-known/did.jsonl': () => new Response('', { status: 404 }) }))).rejects.toThrow('log was not found')
    // a pointer to an address, or to a host that is not a domain name, is not followed
    const asked: string[] = []
    await expect(resolveMailAddressDid('alice@example.org', [], world(asked, answer('https://127.0.0.1')))).rejects.toThrow('which is not a DID')
    expect(asked.some(url => url.includes('127.0.0.1'))).toBe(false)
  })
})
