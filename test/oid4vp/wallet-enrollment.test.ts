import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { encodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { BisetOid4vpWallet } from '../../src/oid4vp/wallet.ts'
import type { BisetLoginWalletCredentialStore } from '../../src/oid4vp/wallet-store.ts'

const store = {} as BisetLoginWalletCredentialStore
const trust = {
  issuer: 'https://anchor.biset.md',
  credentialSigningKeyId: 'https://anchor.biset.md/oid4vp/jwks#key-1',
  credentialSigningPublicKey: {
    kty: 'EC' as const,
    crv: 'P-256' as const,
    x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  },
}

describe('Biset Wallet enrollment authority', () => {
  test('accepts only the exact did:key verification method derived from the Sign key', async () => {
    const signPrivateKey = new Uint8Array(32).fill(7)
    const multikey = encodeMultikey(ed25519.getPublicKey(signPrivateKey))
    let requests = 0
    const wallet = new BisetOid4vpWallet({
      identityId: 'did:webvh:example.test', generation: '1-test', trust, store,
      fetch: async () => {
        requests += 1
        return requests === 1
          ? Response.json({ document: { challenge: 'test' } })
          : new Response('stop after proof construction', { status: 500 })
      },
    })

    await expect(wallet.enroll({
      did: 'did:webvh:example.test',
      authenticationVerificationMethod: `did:key:${multikey}#${multikey}`,
      authenticationPrivateKey: signPrivateKey,
    })).rejects.toThrow('Anchor enrollment failed (500)')
    expect(requests).toBe(2)

    await expect(wallet.enroll({
      did: 'did:webvh:example.test',
      authenticationVerificationMethod: 'did:key:zWrong#zWrong',
      authenticationPrivateKey: signPrivateKey,
    })).rejects.toThrow('Anchor enrollment authority is invalid')
    expect(requests).toBe(2)
  })
})
