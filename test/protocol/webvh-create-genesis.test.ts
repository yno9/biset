// createGenesis (write path) against a fake in-memory anchor, then resolve
// (read path, src/protocol/webvh/resolver.ts) against the same log --
// confirms the two sides of this resolver actually agree on the wire
// format, not just that each independently accepts its own fixtures.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../src/client/identity/webvh/create-genesis.ts'
import { resolve } from '../../src/protocol/webvh/resolver.ts'
import { decodeMultikey } from '../../src/protocol/webvh/multikey.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'

describe('createGenesis + resolve', () => {
  test('a genesis this module writes is exactly what the read-only resolver accepts', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const anchor = fakeAnchor()

    const { did, scid } = await createGenesis({ domain: 'test.example', pathSegments: ['alice'], rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    expect(did).toBe(`did:webvh:${scid}:test.example:alice`)

    const realFetch = globalThis.fetch
    globalThis.fetch = anchor.fetch
    try {
      const doc = await resolve(did)
      expect(doc?.id).toBe(did)
      expect(doc?.verificationMethod).toHaveLength(1)
      expect(doc?.verificationMethod[0]?.id).toBe(`${did}#key-1`)
      expect(decodeMultikey(doc!.verificationMethod[0]!.publicKeyMultibase)).toEqual(rootPublicKey)
      expect(doc?.authentication).toEqual([`${did}#key-1`])
      // No service at genesis: the `#routing` pointer went away with
      // routing.json (2026-09-16), and the `#didcomm` service is appended
      // later by did.md Wallet's document edit.
      expect(doc?.service).toEqual([])
      expect(doc?.alsoKnownAs).toEqual([])
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('rejects when the PUT fails', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const failingFetch = (async () => new Response('server error', { status: 500 })) as typeof fetch
    await expect(createGenesis({ domain: 'test.example', rootPrivateKey, rootPublicKey, fetch: failingFetch })).rejects.toThrow('PUT failed')
  })
})
