import { afterEach, describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createPersistentAnchorOid4vpOidcProvider, createPersistentAnchorOidcProvider } from '../../src/anchor/oidc-deployment.ts'

const directories: string[] = []
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }) })

const client = {
  clientId: 'biset-client',
  redirectUris: ['https://app.biset.md/oauth/callback'],
  sectorIdentifier: 'biset.md',
  audience: 'https://coordinator.biset.md',
  allowedScopes: ['vault.pull'],
}

describe('persistent Anchor OIDC composition', () => {
  test('keeps the issuer signing key stable across process restarts', () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'anchor-oidc-deployment-'))
    directories.push(dataDir)
    const options = {
      dataDir,
      issuer: 'https://anchor.biset.md',
      clients: [client],
      authenticator: { authenticate: async () => ({ subject: 'account-1' }) },
    }
    const first = createPersistentAnchorOidcProvider(options)
    const firstJwks = first.provider.jwks()
    first.close()

    const second = createPersistentAnchorOidcProvider(options)
    expect(second.provider.jwks()).toEqual(firstJwks)
    expect(second.provider.metadata()).toMatchObject({
      issuer: 'https://anchor.biset.md',
      authorization_endpoint: 'https://anchor.biset.md/oauth/authorize',
      token_endpoint: 'https://anchor.biset.md/oauth/token',
    })
    second.close()
  })

  test('closes the SQLite state when provider validation fails', () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'anchor-oidc-invalid-'))
    directories.push(dataDir)
    expect(() => createPersistentAnchorOidcProvider({
      dataDir,
      issuer: 'http://anchor.biset.md',
      clients: [client],
      authenticator: { authenticate: async () => null },
    })).toThrow('OIDC issuer must be an HTTPS origin')

    const valid = createPersistentAnchorOidcProvider({
      dataDir,
      issuer: 'https://anchor.biset.md',
      clients: [client],
      authenticator: { authenticate: async () => null },
    })
    valid.close()
  })

  test('composes OID4VP as the sole interactive authenticator with stable independent keys', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'anchor-oid4vp-composition-'))
    directories.push(dataDir)
    const first = createPersistentAnchorOid4vpOidcProvider({ dataDir, issuer: 'https://anchor.biset.md', clients: [client] })
    const oidcJwks = first.oidc.jwks()
    const credentialJwks = first.oid4vp.jwks()
    expect(credentialJwks).not.toEqual(oidcJwks)
    first.close()

    const second = createPersistentAnchorOid4vpOidcProvider({ dataDir, issuer: 'https://anchor.biset.md', clients: [client] })
    expect(second.oidc.jwks()).toEqual(oidcJwks)
    expect(second.oid4vp.jwks()).toEqual(credentialJwks)
    const challenge = await second.oidc.authorize(new Request('https://anchor.biset.md/oauth/authorize?response_type=code&client_id=biset-client&redirect_uri=https%3A%2F%2Fapp.biset.md%2Foauth%2Fcallback&scope=openid&state=s&nonce=n&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256&wallet_origin=null'))
    expect(challenge.status).toBe(302)
    expect(new URL(challenge.headers.get('location')!).pathname).toBe('/oid4vp/wallet-bridge')
    second.close()
  })
})
