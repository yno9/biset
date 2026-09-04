import { describe, expect, test } from 'bun:test'
import { p256 } from '@noble/curves/nist.js'
import { AnchorOidcProvider, MemoryAnchorAuthorizationCodeStore } from '../src/anchor/oidc.ts'
import { AnchorOid4vpProvider, MemoryAnchorOid4vpStore } from '../src/anchor/oid4vp.ts'

const issuer = 'https://biset.md'

describe('Anchor wallet application origin', () => {
  test('allows only a statically registered file or HTTPS wallet origin', async () => {
    const provider = new AnchorOidcProvider({
      issuer,
      clients: [{
        clientId: 'biset-client', redirectUris: [`${issuer}/oauth/client-callback`],
        applicationOrigins: ['null', 'https://t.biset.md'], sectorIdentifier: 'biset-client',
        audience: 'https://coordinator.biset.md', allowedScopes: ['vault.pull'],
      }],
      authenticator: {
        async authenticate() { return null },
        async beginAuthentication() { return new Response('login-started', { status: 202 }) },
      },
      codes: new MemoryAnchorAuthorizationCodeStore(),
      signingPrivateKey: p256.utils.randomSecretKey(), pairwiseSecret: crypto.getRandomValues(new Uint8Array(32)),
    })
    const authorize = (walletOrigin: string) => {
      const url = new URL(`${issuer}/oauth/authorize`)
      for (const [key, value] of Object.entries({
        client_id: 'biset-client', redirect_uri: `${issuer}/oauth/client-callback`, response_type: 'code',
        wallet_origin: walletOrigin, scope: 'openid vault.pull', state: 'state', nonce: 'nonce',
        code_challenge: 'a'.repeat(43), code_challenge_method: 'S256',
      })) url.searchParams.set(key, value)
      return provider.authorize(new Request(url))
    }

    expect((await authorize('null')).status).toBe(202)
    expect((await authorize('https://t.biset.md')).status).toBe(202)
    const rejected = await authorize('https://evil.example')
    expect(rejected.status).toBe(302)
    expect(new URL(rejected.headers.get('location')!).searchParams.get('error')).toBe('invalid_request')
  })

  test('binds the wallet bridge to the validated opener origin', async () => {
    const provider = new AnchorOid4vpProvider({
      issuer, store: new MemoryAnchorOid4vpStore(), credentialSigningPrivateKey: p256.utils.randomSecretKey(),
    })
    const response = await provider.beginAuthentication(new Request(`${issuer}/oauth/authorize?wallet_origin=${encodeURIComponent('https://t.biset.md')}`))
    const destination = new URL(response.headers.get('location')!)
    expect(destination.searchParams.get('opener_origin')).toBe('https://t.biset.md')
    const script = await provider.walletBridgeScript().text()
    expect(script).toContain("event.origin !== openerOrigin")
    expect(script).toContain("openerOrigin === 'null' ? '*' : openerOrigin")
  })
})
