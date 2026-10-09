import { describe, expect, test } from 'bun:test'
import { didWebDidCommRoute, resolveDidWeb, type DidWebDocument } from '../../src/protocol/didcomm/did-web.ts'
import { encodeX25519Multikey } from '../../src/protocol/didcomm/multikey.ts'

const DID = 'did:web:smtp.example'
const key = encodeX25519Multikey(new Uint8Array(32).fill(7))
const base = (serviceEndpoint: unknown): DidWebDocument => ({
  id: DID,
  verificationMethod: [{ id: `${DID}#k1`, type: 'Multikey', controller: DID, publicKeyMultibase: key }],
  keyAgreement: [`${DID}#k1`],
  service: [{ id: `${DID}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint }],
})
const entry = (uri: string) => ({ uri, accept: ['didcomm/v2'], routingKeys: [] })

describe('didWebDidCommRoute with a published set', () => {
  test('reads the canonical entry of a set; a single map is unchanged', () => {
    expect(didWebDidCommRoute(base([entry('http://x.onion'), entry('https://smtp.example')])).uri).toBe('https://smtp.example')
    expect(didWebDidCommRoute(base(entry('https://smtp.example'))).uri).toBe('https://smtp.example')
  })
  test('an onion-only set has no route', () => {
    expect(() => didWebDidCommRoute(base([entry('http://x.onion')]))).toThrow('no DIDComm route')
  })
})

describe('resolveDidWeb paths', () => {
  const fetched: string[] = []
  const fetchImpl = (async (input: string | URL | Request) => { fetched.push(String(input)); return new Response('Not found', { status: 404 }) }) as typeof fetch
  test('a percent-encoded segment (a mail bridge address DID) is kept encoded in the URL', async () => {
    expect(await resolveDidWeb('did:web:did.md:gmail.com:bob%2Bnews', fetchImpl)).toBeNull()
    expect(fetched.at(-1)).toBe('https://did.md/gmail.com/bob%2Bnews/did.json')
  })
  test('other characters, a bare `%`, and dot segments are refused', async () => {
    for (const did of ['did:web:did.md:gmail.com:bob+news', 'did:web:did.md:gmail.com:bob%2', 'did:web:did.md:..:x', 'did:web:did.md::x']) {
      await expect(resolveDidWeb(did, fetchImpl)).rejects.toThrow('invalid did:web path')
    }
  })
})
