// GET/PUT .well-known/routing.json against a real RoutingDocStore +
// WebvhLogStore pair, confirming the client-side publishRoutingPointer
// (the signed `#routing` log entry) and putRouting/fetchRouting (the
// DataIntegrityProof-checked routing.json write) round-trip against this
// server, and that a proof signed by a non-updateKey is rejected.
import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../../src/identity/webvh/create-genesis.ts'
import { createWebvhHttpHandler } from '../../../src/anchor/webvh/webvh-http.ts'
import { WebvhLogStore } from '../../../src/anchor/webvh/webvh-store.ts'
import { createRoutingHttpHandler } from '../../../src/anchor/webvh/routing-http.ts'
import { RoutingDocStore } from '../../../src/anchor/webvh/routing-store.ts'
import { publishRoutingPointer } from '../../../src/didcomm/webvh-routing-pointer.ts'
import { buildRoutingDoc, fetchRouting, putRouting } from '../../../src/didcomm/webvh-routing.ts'
import { buildProof } from '../../../src/identity/webvh/proof.ts'
import { encodeMultikey } from '../../../src/identity/webvh/multikey.ts'

function testFetch(webvhHandler: (r: Request) => Promise<Response>, routingHandler: (r: Request) => Promise<Response>, domain: string): typeof fetch {
  return (async (input, init) => {
    const url = typeof input === 'string' ? input : input.toString()
    const headers = new Headers(init?.headers)
    headers.set('host', domain)
    const request = new Request(url, { ...init, headers })
    return new URL(url).pathname === '/.well-known/routing.json' ? routingHandler(request) : webvhHandler(request)
  }) as typeof fetch
}

function withStores<T>(run: (webvh: WebvhLogStore, routing: RoutingDocStore) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'routing-http-test-'))
  return run(new WebvhLogStore(dir), new RoutingDocStore(dir)).finally(() => rmSync(dir, { recursive: true, force: true }))
}

describe('createRoutingHttpHandler', () => {
  test('GET on an unknown domain is 404', () => withStores(async (webvh, routing) => {
    const handler = createRoutingHttpHandler(routing, webvh)
    const res = await handler(new Request('https://alice.test.example/.well-known/routing.json', { headers: { host: 'alice.test.example' } }))
    expect(res.status).toBe(404)
  }))

  test('PUT with no did:webvh identity at the domain is 404', () => withStores(async (webvh, routing) => {
    const handler = createRoutingHttpHandler(routing, webvh)
    const res = await handler(new Request('https://alice.test.example/.well-known/routing.json', {
      method: 'PUT', headers: { host: 'alice.test.example' }, body: JSON.stringify({ proof: {} }),
    }))
    expect(res.status).toBe(404)
  }))

  test('publishRoutingPointer + putRouting round-trip: the signed #routing entry and routing.json both land, GET returns keyAgreement/service', () => withStores(async (webvh, routing) => {
    const webvhHandler = createWebvhHttpHandler(webvh)
    const routingHandler = createRoutingHttpHandler(routing, webvh)
    const fetchImpl = testFetch(webvhHandler, routingHandler, 'alice.test.example')
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did } = await createGenesis({ domain: 'alice.test.example', rootPrivateKey, rootPublicKey, fetch: fetchImpl })

    await publishRoutingPointer({ did, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, fetch: fetchImpl })

    const deviceX25519Priv = x25519.utils.randomSecretKey()
    const deviceX25519Pub = x25519.getPublicKey(deviceX25519Priv)
    const doc = buildRoutingDoc(did, {
      didCommEndpoint: 'https://biset.test.example/v1/didcomm/ingress',
      keyAgreementKeys: [{ kid: '#k_test', publicKey: deviceX25519Pub }],
    })
    const updateKey = encodeMultikey(rootPublicKey)
    await putRouting(did, doc, { updateKey, privateKey: rootPrivateKey }, fetchImpl)

    const fetched = await fetchRouting(did, fetchImpl)
    expect(fetched?.service[0]?.type).toBe('DIDCommMessaging')
    expect(fetched?.keyAgreementVerificationMethod?.[0]?.id).toBe(`${did}#k_test`)

    // Confirm the pointer really did land in the SIGNED log, not just
    // routing.json's own content.
    const logRes = await webvhHandler(new Request(`https://alice.test.example/.well-known/did.jsonl`, { headers: { host: 'alice.test.example' } }))
    const logText = await logRes.text()
    expect(logText).toContain('"BisetRoutingDocument"')
  }))

  test('a routing.json write with a proof from a key that is not a current updateKey is rejected', () => withStores(async (webvh, routing) => {
    const webvhHandler = createWebvhHttpHandler(webvh)
    const routingHandler = createRoutingHttpHandler(routing, webvh)
    const fetchImpl = testFetch(webvhHandler, routingHandler, 'alice.test.example')
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did } = await createGenesis({ domain: 'alice.test.example', rootPrivateKey, rootPublicKey, fetch: fetchImpl })
    await publishRoutingPointer({ did, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, fetch: fetchImpl })

    const impostorPrivateKey = ed25519.utils.randomSecretKey()
    const impostorPublicKey = ed25519.getPublicKey(impostorPrivateKey)
    const impostorKey = encodeMultikey(impostorPublicKey)
    const doc = buildRoutingDoc(did, { didCommEndpoint: 'https://evil.test.example/v1/didcomm/ingress' })
    const proof = buildProof(doc, { verificationMethod: `did:key:${impostorKey}#${impostorKey}`, privateKey: impostorPrivateKey })
    const res = await fetchImpl('https://alice.test.example/.well-known/routing.json', {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...doc, proof }),
    })
    expect(res.status).toBe(403)
  }))
})
