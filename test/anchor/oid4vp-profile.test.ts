import { describe, expect, test } from 'bun:test'
import { p256 } from '@noble/curves/nist.js'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'
import {
  accountRefFromCredential,
  createBisetLoginPresentation,
  issueBisetAnchorLoginCredential,
  p256PublicJwk,
  verifyBisetAnchorLoginCredential,
  verifyBisetLoginPresentation,
} from '../../src/oid4vp/profile.ts'

const issuer = 'https://anchor.biset.md'
const keyId = `${issuer}/oid4vp/jwks#login-credential-es256-1`
const issuerPrivateKey = new Uint8Array(32).fill(11)
const holderPrivateKey = new Uint8Array(32).fill(12)
const now = new Date('2026-08-28T08:00:00.000Z')
const accountRef = bytesToBase64url(new Uint8Array(32).fill(13))
const generation = `1-${'a'.repeat(32)}`

function credential(): string {
  return issueBisetAnchorLoginCredential({
    issuer, signingKeyId: keyId, signingPrivateKey: issuerPrivateKey,
    accountRef, generation, holderPublicKey: p256PublicJwk(holderPrivateKey),
    validFrom: new Date(now.getTime() - 60_000), validUntil: new Date(now.getTime() + 86_400_000),
  })
}

describe('Biset Anchor OID4VP profile', () => {
  test('issues a minimal opaque account credential and verifies a holder-bound presentation', () => {
    const token = credential()
    const presentation = createBisetLoginPresentation({ credential: token, holderPrivateKey, verifierId: `${issuer}/oid4vp/response`, nonce: 'request-nonce', now })
    const verified = verifyBisetLoginPresentation(presentation, {
      verifierId: `${issuer}/oid4vp/response`, nonce: 'request-nonce', issuer,
      credentialSigningKeyId: keyId, credentialSigningPublicKey: p256PublicJwk(issuerPrivateKey), now,
    })
    expect(accountRefFromCredential(verified.credential)).toBe(accountRef)
    expect(JSON.stringify(verified.credential)).not.toContain('did:')
    expect(JSON.stringify(verified.credential)).not.toContain('vault')
    expect(JSON.stringify(verified.credential)).not.toContain('scid')
    expect(JSON.stringify(verified.credential)).not.toContain('domain')
    expect(JSON.stringify(verified.credential)).not.toContain('mail')
  })

  test('rejects another holder, verifier, nonce, expired credential, and issuer-signature substitution', () => {
    const token = credential()
    expect(() => createBisetLoginPresentation({ credential: token, holderPrivateKey: new Uint8Array(32).fill(14), verifierId: `${issuer}/oid4vp/response`, nonce: 'nonce', now })).not.toThrow()
    const wrongHolder = createBisetLoginPresentation({ credential: token, holderPrivateKey: new Uint8Array(32).fill(14), verifierId: `${issuer}/oid4vp/response`, nonce: 'nonce', now })
    const verify = (presentation: string, overrides: Partial<{ verifierId: string; nonce: string; now: Date }> = {}) => verifyBisetLoginPresentation(presentation, {
      verifierId: overrides.verifierId ?? `${issuer}/oid4vp/response`, nonce: overrides.nonce ?? 'nonce', issuer,
      credentialSigningKeyId: keyId, credentialSigningPublicKey: p256PublicJwk(issuerPrivateKey), now: overrides.now ?? now,
    })
    expect(() => verify(wrongHolder)).toThrow('JWT signature is invalid')
    const valid = createBisetLoginPresentation({ credential: token, holderPrivateKey, verifierId: `${issuer}/oid4vp/response`, nonce: 'nonce', now })
    expect(() => verify(valid, { verifierId: 'https://evil.example/response' })).toThrow('presentation session binding is invalid')
    expect(() => verify(valid, { nonce: 'another' })).toThrow('presentation session binding is invalid')
    expect(() => verify(valid, { now: new Date(now.getTime() + 86_500_000) })).toThrow('credential is outside its validity period')
    expect(() => verifyBisetAnchorLoginCredential(token, { issuer, signingKeyId: keyId, signingPublicKey: p256PublicJwk(new Uint8Array(32).fill(15)), now })).toThrow('JWT signature is invalid')
  })
})
