import { describe, expect, test } from 'bun:test'
import { sha256 } from '@noble/hashes/sha2.js'
import { AnchorOidcProvider, MemoryAnchorAuthorizationCodeStore } from '../../src/anchor/oidc.ts'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'

describe('OIDC identity selection', () => {
  test('prompt=login bypasses an existing Anchor session and starts Wallet authentication', async () => {
    let forced = false
    const provider = new AnchorOidcProvider({
      issuer: 'https://anchor.biset.md',
      clients: [{
        clientId: 'client', redirectUris: ['https://client.example/cb'],
        sectorIdentifier: 'sector', audience: 'https://coordinator.biset.md',
        allowedScopes: ['vault.pull'], applicationOrigins: ['null'],
      }],
      authenticator: {
        async authenticate(_request, options) {
          forced = options?.force === true
          return options?.force ? null : { subject: 'stale-browser-session' }
        },
        async beginAuthentication() { return new Response('wallet login', { status: 202 }) },
      },
      codes: new MemoryAnchorAuthorizationCodeStore(),
      signingPrivateKey: new Uint8Array(32).fill(5),
      pairwiseSecret: new Uint8Array(32).fill(6),
    })
    const verifier = 'y'.repeat(43)
    const url = new URL('https://anchor.biset.md/oauth/authorize')
    const values = {
      response_type: 'code', client_id: 'client', redirect_uri: 'https://client.example/cb',
      scope: 'openid vault.pull', state: 's', nonce: 'n',
      code_challenge: bytesToBase64url(sha256(new TextEncoder().encode(verifier))),
      code_challenge_method: 'S256', wallet_origin: 'null', prompt: 'login',
    }
    for (const [key, value] of Object.entries(values)) url.searchParams.set(key, value)

    const response = await provider.authorize(new Request(url))
    expect(forced).toBeTrue()
    expect(response.status).toBe(202)
    expect(await response.text()).toBe('wallet login')
  })
})
