import { describe, expect, test } from 'bun:test'
import { sha256 } from '@noble/hashes/sha2.js'
import { AnchorOidcProvider, MemoryAnchorAuthorizationCodeStore } from '../../src/anchor/oidc.ts'
import { AnchorOid4vpProvider, MemoryAnchorOid4vpStore } from '../../src/anchor/oid4vp.ts'
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
          return options?.force ? null : { subject: 'stale-browser-session', generation: `1-${'a'.repeat(32)}` }
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

  test('Wallet authentication consumes prompt=login before returning to authorize', async () => {
    const store = new MemoryAnchorOid4vpStore()
    const oid4vp = new AnchorOid4vpProvider({
      issuer: 'https://anchor.biset.md', store,
      credentialSigningPrivateKey: new Uint8Array(32).fill(7),
    })
    const response = await oid4vp.beginAuthentication(new Request(
      'https://anchor.biset.md/oauth/authorize?client_id=client&state=s&wallet_origin=null&prompt=login',
    ))
    const location = new URL(response.headers.get('location')!)
    const requestUri = new URL(location.searchParams.get('request_uri')!)
    const transaction = await store.transaction(requestUri.pathname.split('/').pop()!)
    const returnUrl = new URL(transaction!.returnUrl)
    expect(returnUrl.searchParams.get('prompt')).toBeNull()
    expect(returnUrl.searchParams.get('client_id')).toBe('client')
    expect(returnUrl.searchParams.get('state')).toBe('s')
  })
})
