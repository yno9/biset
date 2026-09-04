// GET/PUT/POST .well-known/did.jsonl against a real WebvhLogStore (tmp dir)
// and createWebvhHttpHandler -- confirms the server side actually accepts
// what identity/webvh/create-genesis.ts (the client side) writes for the
// subdomain-per-identity scheme, and that resolve() reads it back correctly.
// This is the server half `test/protocol/webvh-create-genesis.test.ts`
// exercises against a fake in-memory anchor instead.
import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../../src/identity/webvh/create-genesis.ts'
import { resolve } from '../../../src/identity/webvh/resolver.ts'
import { createWebvhHttpHandler } from '../../../src/anchor/webvh/webvh-http.ts'
import { WebvhLogStore } from '../../../src/anchor/webvh/webvh-store.ts'

function testFetch(handler: (request: Request) => Promise<Response>, domain: string): typeof fetch {
  return (async (input, init) => {
    const url = typeof input === 'string' ? input : input.toString()
    const headers = new Headers(init?.headers)
    headers.set('host', domain)
    return handler(new Request(url, { ...init, headers }))
  }) as typeof fetch
}

function withStore<T>(run: (store: WebvhLogStore) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'webvh-http-test-'))
  return run(new WebvhLogStore(dir)).finally(() => rmSync(dir, { recursive: true, force: true }))
}

describe('createWebvhHttpHandler', () => {
  test('GET on an unknown domain is 404', () => withStore(async store => {
    const handler = createWebvhHttpHandler(store)
    const res = await handler(new Request('https://alice.test.example/.well-known/did.jsonl', { headers: { host: 'alice.test.example' } }))
    expect(res.status).toBe(404)
  }))

  test('genesis PUT then GET round-trips through resolve()', () => withStore(async store => {
    const handler = createWebvhHttpHandler(store)
    const fetchImpl = testFetch(handler, 'alice.test.example')
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)

    const { did, scid } = await createGenesis({ domain: 'alice.test.example', rootPrivateKey, rootPublicKey, fetch: fetchImpl })
    expect(did).toBe(`did:webvh:${scid}:alice.test.example`)

    // resolve() always uses the real global fetch internally, so swap it for the duration.
    const realFetch = globalThis.fetch
    globalThis.fetch = fetchImpl
    try {
      const resolved = await resolve(did)
      expect(resolved?.id).toBe(did)
      expect(resolved?.verificationMethod).toHaveLength(1)
    } finally {
      globalThis.fetch = realFetch
    }
  }))

  test('two identities on different subdomains do not collide', () => withStore(async store => {
    const handler = createWebvhHttpHandler(store)
    const aliceKey = ed25519.utils.randomSecretKey()
    const bobKey = ed25519.utils.randomSecretKey()
    const { did: aliceDid } = await createGenesis({
      domain: 'alice.test.example', rootPrivateKey: aliceKey, rootPublicKey: ed25519.getPublicKey(aliceKey),
      fetch: testFetch(handler, 'alice.test.example'),
    })
    const { did: bobDid } = await createGenesis({
      domain: 'bob.test.example', rootPrivateKey: bobKey, rootPublicKey: ed25519.getPublicKey(bobKey),
      fetch: testFetch(handler, 'bob.test.example'),
    })
    expect(aliceDid).not.toBe(bobDid)

    const realFetch = globalThis.fetch
    globalThis.fetch = testFetch(handler, 'alice.test.example')
    try {
      expect((await resolve(aliceDid))?.id).toBe(aliceDid)
    } finally {
      globalThis.fetch = realFetch
    }
    globalThis.fetch = testFetch(handler, 'bob.test.example')
    try {
      expect((await resolve(bobDid))?.id).toBe(bobDid)
    } finally {
      globalThis.fetch = realFetch
    }
  }))

  test('a second full-log PUT that does not extend the existing log is rejected', () => withStore(async store => {
    const handler = createWebvhHttpHandler(store)
    const fetchImpl = testFetch(handler, 'alice.test.example')
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    await createGenesis({ domain: 'alice.test.example', rootPrivateKey, rootPublicKey, fetch: fetchImpl })

    const otherFetch = testFetch(handler, 'alice.test.example')
    const res = await otherFetch('https://alice.test.example/.well-known/did.jsonl', {
      method: 'PUT',
      body: JSON.stringify({
        versionId: '1-bogus', versionTime: new Date().toISOString(),
        parameters: { method: 'did:webvh:1.0', scid: 'zBogusScidBogusScidBogusScidBogusScidBogusSc', updateKeys: [], nextKeyHashes: [], portable: true, witness: {}, watchers: [], deactivated: false },
        state: { id: 'did:webvh:zBogus:alice.test.example' },
        proof: [],
      }) + '\n',
    })
    expect(res.status).toBe(409)
  }))
})
