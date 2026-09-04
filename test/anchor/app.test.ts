import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createBisetAnchorDeployment } from '../../src/anchor/deployment.ts'
import { AnchorOidcProvider, MemoryAnchorAuthorizationCodeStore } from '../../src/anchor/oidc.ts'

function withAnchor<T>(run: (fetch: (request: Request) => Promise<Response>) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'biset-anchor-test-'))
  const anchor = createBisetAnchorDeployment({ dataDir: dir })
  return run(anchor.fetch).finally(() => rmSync(dir, { recursive: true, force: true }))
}

describe('biset-anchor application boundary', () => {
  test('identifies itself as a public identity service with OIDC disabled', () => withAnchor(async fetch => {
    const response = await fetch(new Request('https://anchor.test/healthz'))
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({
      ok: true,
      service: 'biset-anchor',
      storage: 'public-identity-only',
      oidc: 'disabled',
      oid4vp: 'disabled',
    })
  }))

  test('does not expose core relay, MLS, mail, roster, or DIDComm paths', () => withAnchor(async fetch => {
    for (const path of [
      '/v1/vault-delivery/pull',
      '/v1/mls/messages',
      '/v1/mail/submit',
      '/v1/roster/install',
      '/v1/didcomm/ingress',
    ]) {
      const response = await fetch(new Request(`https://anchor.test${path}`, { method: 'POST' }))
      expect(response.status).toBe(404)
    }
  }))

  test('reports OIDC control-plane storage only when the provider is enabled', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'biset-anchor-oidc-health-'))
    const oidc = new AnchorOidcProvider({
      issuer: 'https://anchor.test',
      clients: [{ clientId: 'client', redirectUris: ['https://client.test/cb'], sectorIdentifier: 'client.test', audience: 'https://coordinator.test', allowedScopes: [] }],
      authenticator: { authenticate: async () => null },
      codes: new MemoryAnchorAuthorizationCodeStore(),
      signingPrivateKey: new Uint8Array(32).fill(1),
      pairwiseSecret: new Uint8Array(32).fill(2),
    })
    try {
      const anchor = createBisetAnchorDeployment({ dataDir: dir, oidc })
      const response = await anchor.fetch(new Request('https://anchor.test/healthz'))
      expect(await response.json()).toMatchObject({
        storage: 'identity-and-oidc-control-plane',
        oidc: 'enabled',
      })
      const callback = await anchor.fetch(new Request('https://anchor.test/oauth/client-callback?code=opaque&state=opaque'))
      expect(callback.status).toBe(200)
      expect(callback.headers.get('cache-control')).toBe('no-store')
      expect(await callback.text()).toContain('/oauth/client-callback.js')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('owns the public well-known routes', () => withAnchor(async fetch => {
    for (const path of [
      '/.well-known/did.jsonl',
      '/.well-known/did.json',
      '/.well-known/routing.json',
    ]) {
      const response = await fetch(new Request(`https://anchor.test${path}`, {
        headers: { 'x-biset-domain': 'anchor.test' },
      }))
      expect(response.status).toBe(404)
      expect(response.headers.get('access-control-allow-origin')).toBe('*')
    }
  }))
})
