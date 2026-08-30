import { describe, expect, test } from 'bun:test'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'
import { OidcJwtAccessTokenVerifier, VaultAuthenticationError } from '../../src/coordinator/auth.ts'

describe('Vault Coordinator OIDC access-token verification', () => {
  test('discovers JWKS and verifies an audience-bound scoped access token', async () => {
    const keys = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])
    const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey)
    const now = new Date('2026-08-27T00:00:00.000Z')
    const token = await jwt(keys.privateKey, {
      iss: 'https://anchor.biset.md',
      sub: 'pairwise-coordinator-subject',
      aud: 'https://coordinator.biset.md',
      client_id: 'biset-client',
      jti: 'token-1',
      scope: 'vault.create vault.pull',
      biset_generation: `1-${'a'.repeat(32)}`,
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 300,
    })
    const requests: string[] = []
    const verifier = new OidcJwtAccessTokenVerifier({
      issuer: 'https://anchor.biset.md',
      audience: 'https://coordinator.biset.md',
      fetch: async (input) => {
        const url = String(input)
        requests.push(url)
        if (url.endsWith('/.well-known/openid-configuration')) return Response.json({ issuer: 'https://anchor.biset.md', jwks_uri: 'https://anchor.biset.md/oauth/jwks' })
        if (url.endsWith('/oauth/jwks')) return Response.json({ keys: [{ ...publicJwk, kid: 'key-1', alg: 'RS256', use: 'sig' }] })
        return new Response('not found', { status: 404 })
      },
    })
    const principal = await verifier.verify(token, now)
    expect(principal.subject).toBe('pairwise-coordinator-subject')
    expect(principal.generation).toBe(`1-${'a'.repeat(32)}`)
    expect([...principal.scopes]).toEqual(['vault.create', 'vault.pull'])
    expect(requests).toHaveLength(2)
    await verifier.verify(token, now)
    expect(requests).toHaveLength(2)
  })

  test('rejects an ID token-shaped JWT and a wrong audience', async () => {
    const keys = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])
    const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey)
    const fetchImpl: typeof fetch = async () => Response.json({ keys: [{ ...publicJwk, kid: 'key-1', alg: 'RS256' }] })
    const verifier = new OidcJwtAccessTokenVerifier({ issuer: 'https://anchor.biset.md', audience: 'https://coordinator.biset.md', jwksUri: 'https://anchor.biset.md/jwks', fetch: fetchImpl })
    const now = new Date('2026-08-27T00:00:00.000Z')
    const claims = { iss: 'https://anchor.biset.md', sub: 'opaque', aud: 'https://other.example', client_id: 'biset-client', jti: 'token-2', scope: 'vault.pull', biset_generation: `1-${'a'.repeat(32)}`, iat: Math.floor(now.getTime() / 1000), exp: Math.floor(now.getTime() / 1000) + 60 }
    await expect(verifier.verify(await jwt(keys.privateKey, claims), now)).rejects.toBeInstanceOf(VaultAuthenticationError)
    await expect(verifier.verify(await jwt(keys.privateKey, claims, 'JWT'), now)).rejects.toBeInstanceOf(VaultAuthenticationError)
  })
})

async function jwt(privateKey: CryptoKey, claims: Record<string, unknown>, typ = 'at+jwt'): Promise<string> {
  const header = encoded({ alg: 'RS256', kid: 'key-1', typ })
  const payload = encoded(claims)
  const data = new TextEncoder().encode(`${header}.${payload}`)
  const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, data))
  return `${header}.${payload}.${bytesToBase64url(signature)}`
}

function encoded(value: unknown): string {
  return bytesToBase64url(new TextEncoder().encode(JSON.stringify(value)))
}
