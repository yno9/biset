import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { AnchorOidcProvider, MemoryAnchorAuthorizationCodeStore } from '../../src/anchor/oidc.ts'
import { createBisetAnchorDeployment } from '../../src/anchor/deployment.ts'
import { bytesToBase64url, base64urlToBytes } from '../../src/protocol/canonical.ts'
import { sha256 } from '@noble/hashes/sha2.js'

describe('biset-anchor OIDC provider', () => {
  test('issues a pairwise ES256 access token through Code + PKCE and consumes the code once', async () => {
    const now = new Date('2026-08-28T05:00:00.000Z')
    const provider = new AnchorOidcProvider({
      issuer: 'https://anchor.biset.md',
      clients: [{
        clientId: 'biset-client',
        redirectUris: ['https://client.example/callback'],
        sectorIdentifier: 'biset-client-sector',
        audience: 'https://coordinator.biset.md',
        allowedScopes: ['vault.create', 'vault.append', 'vault.pull', 'vault.ack'],
        applicationOrigins: ['null'],
      }],
      authenticator: { async authenticate(request) { return request.headers.get('x-test-user') === 'alice' ? { subject: 'anchor-account-alice', generation: `1-${'a'.repeat(32)}`, authenticatedAt: now } : null } },
      codes: new MemoryAnchorAuthorizationCodeStore(),
      signingPrivateKey: new Uint8Array(32).fill(1),
      pairwiseSecret: new Uint8Array(32).fill(2),
      now: () => now,
    })
    const directory = mkdtempSync(join(tmpdir(), 'biset-anchor-oidc-'))
    const anchor = createBisetAnchorDeployment({ dataDir: directory, oidc: provider })
    try {
      const verifierValue = 'v'.repeat(43)
      const challenge = bytesToBase64url(sha256(new TextEncoder().encode(verifierValue)))
      const authorizationUrl = new URL('https://anchor.biset.md/oauth/authorize')
      for (const [name, value] of Object.entries({
        response_type: 'code', client_id: 'biset-client', redirect_uri: 'https://client.example/callback',
        scope: 'openid vault.create vault.pull', state: 'browser-state', nonce: 'browser-nonce',
        code_challenge: challenge, code_challenge_method: 'S256', wallet_origin: 'null',
      })) authorizationUrl.searchParams.set(name, value)
      const authorization = await anchor.fetch(new Request(authorizationUrl, { headers: { 'x-test-user': 'alice' } }))
      expect(authorization.status).toBe(302)
      const callback = new URL(authorization.headers.get('location')!)
      expect(callback.searchParams.get('state')).toBe('browser-state')
      const code = callback.searchParams.get('code')!

      const form = new URLSearchParams({ grant_type: 'authorization_code', client_id: 'biset-client', redirect_uri: 'https://client.example/callback', code, code_verifier: verifierValue })
      const tokenResponse = await anchor.fetch(new Request('https://anchor.biset.md/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form }))
      expect(tokenResponse.status).toBe(200)
      expect(tokenResponse.headers.get('access-control-allow-origin')).toBe('*')
      const tokens = await tokenResponse.json() as { access_token: string; id_token: string; refresh_token: string; scope: string }
      expect(tokens.scope).toBe('vault.create vault.pull')
      const idClaims = jwtClaims(tokens.id_token)
      expect(idClaims.nonce).toBe('browser-nonce')
      expect(idClaims.sub).not.toBe('anchor-account-alice')

      // No cryptographic verifier is exercised here any more -- the
      // RFC 9068 at+jwt verifier that used to check this token's signature
      // lived in the retired Coordinator backend (src/coordinator/auth.ts)
      // and was deleted along with it. Decoding the claims directly still
      // covers what AnchorOidcProvider itself is responsible for: minting a
      // pairwise subject, narrowing scope to what was actually granted, and
      // carrying the caller's WebVH generation through as a plain claim.
      const accessClaims = jwtClaims(tokens.access_token)
      expect(accessClaims.scope).toBe('vault.create vault.pull')
      expect(accessClaims.sub).toBe(idClaims.sub)
      expect(accessClaims.biset_generation).toBe(`1-${'a'.repeat(32)}`)

      const refreshForm = new URLSearchParams({ grant_type: 'refresh_token', client_id: 'biset-client', refresh_token: tokens.refresh_token })
      const refreshed = await anchor.fetch(new Request('https://anchor.biset.md/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: refreshForm }))
      expect(refreshed.status).toBe(200)
      const refreshedTokens = await refreshed.json() as { access_token: string; refresh_token: string }
      expect(refreshedTokens.refresh_token).not.toBe(tokens.refresh_token)
      expect(jwtClaims(refreshedTokens.access_token).sub).toBe(idClaims.sub)
      expect((await anchor.fetch(new Request('https://anchor.biset.md/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: refreshForm }))).status).toBe(400)

      const replay = await anchor.fetch(new Request('https://anchor.biset.md/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form }))
      expect(replay.status).toBe(400)
      expect(await replay.json()).toMatchObject({ error: 'invalid_grant' })
    } finally {
      rmSync(directory, { recursive: true, force: true })
    }
  })

  test('does not mint an authorization code without an authenticated Anchor session', async () => {
    const provider = new AnchorOidcProvider({
      issuer: 'https://anchor.biset.md',
      clients: [{ clientId: 'client', redirectUris: ['https://client.example/cb'], sectorIdentifier: 'sector', audience: 'https://coordinator.biset.md', allowedScopes: ['vault.pull'], applicationOrigins: ['null'] }],
      authenticator: { async authenticate() { return null } }, codes: new MemoryAnchorAuthorizationCodeStore(),
      signingPrivateKey: new Uint8Array(32).fill(3), pairwiseSecret: new Uint8Array(32).fill(4),
    })
    const verifier = 'x'.repeat(43)
    const url = new URL('https://anchor.biset.md/oauth/authorize')
    for (const [key, value] of Object.entries({ response_type: 'code', client_id: 'client', redirect_uri: 'https://client.example/cb', scope: 'openid vault.pull', state: 's', nonce: 'n', code_challenge: bytesToBase64url(sha256(new TextEncoder().encode(verifier))), code_challenge_method: 'S256', wallet_origin: 'null' })) url.searchParams.set(key, value)
    expect((await provider.authorize(new Request(url))).status).toBe(401)
  })

})

function jwtClaims(token: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64urlToBytes(token.split('.')[1]!))) as Record<string, unknown>
}
