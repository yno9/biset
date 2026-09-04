import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { AnchorOid4vpProvider, MemoryAnchorOid4vpStore } from '../../src/anchor/oid4vp.ts'
import { WebvhLogStore } from '../../src/anchor/webvh/webvh-store.ts'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { buildProof } from '../../src/identity/webvh/proof.ts'
import { encodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { multikeyHashBase58 } from '../../src/identity/webvh/hash.ts'
import { BISET_LOGIN_CREDENTIAL_FORMAT, p256PublicJwk, verifyBisetAnchorLoginCredential } from '../../src/oid4vp/profile.ts'

describe('Anchor OID4VP enrollment', () => {
  test('accepts a current-Sign-authenticated challenge with the persisted generation', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'biset-anchor-enrollment-'))
    try {
      const rootPrivateKey = ed25519.utils.randomSecretKey()
      const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
      const sparePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
      let log = ''
      const genesis = await createGenesis({
        domain: 'enrollment.example', rootPrivateKey, rootPublicKey,
        nextKeyHash: multikeyHashBase58(encodeMultikey(sparePublicKey)),
        fetch: async (_input, init) => { log = String(init?.body ?? ''); return new Response(null, { status: 204 }) },
      })
      const webvh = new WebvhLogStore(directory)
      webvh.write('enrollment.example', log)
      const now = new Date('2026-08-28T12:00:00.789Z')
      const credentialSigningPrivateKey = p256.utils.randomSecretKey()
      const provider = new AnchorOid4vpProvider({
        issuer: 'https://anchor.example', store: new MemoryAnchorOid4vpStore(),
        credentialSigningPrivateKey, now: () => now,
      })
      const holderPrivateKey = p256.utils.randomSecretKey()
      const challengeResponse = await provider.beginEnrollment(new Request('https://anchor.example/oid4vp/enrollment/challenge', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ did: genesis.did, holder_jwk: p256PublicJwk(holderPrivateKey) }),
      }), webvh)
      const challenge = await challengeResponse.json() as { document: Record<string, unknown> }
      expect(challengeResponse.status).toBe(200)
      expect(challenge.document.expires_at).toBe('2026-08-28T12:05:00.000Z')

      const proof = buildProof(challenge.document, {
        verificationMethod: `did:key:${encodeMultikey(rootPublicKey)}#${encodeMultikey(rootPublicKey)}`, proofPurpose: 'authentication',
        privateKey: rootPrivateKey, created: now.toISOString(),
      })
      const completion = await provider.completeEnrollment(new Request('https://anchor.example/oid4vp/enrollment/complete', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ document: challenge.document, proof }),
      }), webvh)
      expect(completion.status).toBe(201)
      const issued = await completion.json() as { format: string; credential: string }
      expect(issued.format).toBe(BISET_LOGIN_CREDENTIAL_FORMAT)
      const claims = verifyBisetAnchorLoginCredential(issued.credential, {
        issuer: 'https://anchor.example',
        signingKeyId: 'https://anchor.example/oid4vp/jwks#login-credential-es256-1',
        signingPublicKey: p256PublicJwk(credentialSigningPrivateKey),
        now: new Date(now.getTime() - 2_000),
      })
      expect(claims.credentialSubject.generation).toBe(genesis.versionId)
    } finally {
      rmSync(directory, { recursive: true, force: true })
    }
  })
})
