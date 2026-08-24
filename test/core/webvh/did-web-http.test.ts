// GET/PUT .well-known/did.json against a real DidWebStore + WebvhLogStore
// pair, confirming syncDidWebMirror (identity/web/mirror.ts, the client
// side) can actually publish against this server, and that a mirror write
// not matching the domain's real did:webvh state is rejected.
import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../../src/identity/webvh/create-genesis.ts'
import { syncDidWebMirror } from '../../../src/identity/web/mirror.ts'
import { buildMinimalWebvhState } from '../../../src/identity/webvh/document.ts'
import { createWebvhHttpHandler } from '../../../src/core/webvh/webvh-http.ts'
import { WebvhLogStore } from '../../../src/core/webvh/webvh-store.ts'
import { createDidWebHttpHandler } from '../../../src/core/webvh/did-web-http.ts'
import { DidWebStore } from '../../../src/core/webvh/did-web-store.ts'

function testFetch(webvhHandler: (r: Request) => Promise<Response>, didWebHandler: (r: Request) => Promise<Response>, domain: string): typeof fetch {
  return (async (input, init) => {
    const url = typeof input === 'string' ? input : input.toString()
    const headers = new Headers(init?.headers)
    headers.set('host', domain)
    const request = new Request(url, { ...init, headers })
    return new URL(url).pathname === '/.well-known/did.json' ? didWebHandler(request) : webvhHandler(request)
  }) as typeof fetch
}

function withStores<T>(run: (webvh: WebvhLogStore, didWeb: DidWebStore) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'did-web-http-test-'))
  return run(new WebvhLogStore(dir), new DidWebStore(dir)).finally(() => rmSync(dir, { recursive: true, force: true }))
}

describe('createDidWebHttpHandler', () => {
  test('GET on an unknown domain is 404', () => withStores(async (webvh, didWeb) => {
    const handler = createDidWebHttpHandler(didWeb, webvh)
    const res = await handler(new Request('https://alice.test.example/.well-known/did.json', { headers: { host: 'alice.test.example' } }))
    expect(res.status).toBe(404)
  }))

  test('PUT with no did:webvh identity at the domain is 404', () => withStores(async (webvh, didWeb) => {
    const handler = createDidWebHttpHandler(didWeb, webvh)
    const res = await handler(new Request('https://alice.test.example/.well-known/did.json', {
      method: 'PUT', headers: { host: 'alice.test.example' }, body: '{}',
    }))
    expect(res.status).toBe(404)
  }))

  test('syncDidWebMirror publishes what buildMinimalWebvhState + resolveEntries reconstruct, GET returns it', () => withStores(async (webvh, didWeb) => {
    const webvhHandler = createWebvhHttpHandler(webvh)
    const didWebHandler = createDidWebHttpHandler(didWeb, webvh)
    const fetchImpl = testFetch(webvhHandler, didWebHandler, 'alice.test.example')
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)

    const { did } = await createGenesis({ domain: 'alice.test.example', rootPrivateKey, rootPublicKey, fetch: fetchImpl })
    const state = buildMinimalWebvhState(did, rootPublicKey)
    await syncDidWebMirror(did, state, { domain: 'alice.test.example', fetch: fetchImpl })

    const res = await didWebHandler(new Request('https://alice.test.example/.well-known/did.json', { headers: { host: 'alice.test.example' } }))
    expect(res.status).toBe(200)
    const doc = await res.json() as { id: string }
    expect(doc.id).toBe(`did:web:alice.test.example`)
  }))

  test('a mirror write not matching the current did:webvh state is rejected', () => withStores(async (webvh, didWeb) => {
    const webvhHandler = createWebvhHttpHandler(webvh)
    const didWebHandler = createDidWebHttpHandler(didWeb, webvh)
    const fetchImpl = testFetch(webvhHandler, didWebHandler, 'alice.test.example')
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    await createGenesis({ domain: 'alice.test.example', rootPrivateKey, rootPublicKey, fetch: fetchImpl })

    const res = await didWebHandler(new Request('https://alice.test.example/.well-known/did.json', {
      method: 'PUT', headers: { host: 'alice.test.example', 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'did:web:alice.test.example', verificationMethod: [] }),
    }))
    expect(res.status).toBe(403)
  }))
})
