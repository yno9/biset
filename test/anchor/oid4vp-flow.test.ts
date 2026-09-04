import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { createBisetAnchorDeployment } from '../../src/anchor/deployment.ts'
import { AnchorOidcProvider, MemoryAnchorAuthorizationCodeStore } from '../../src/anchor/oidc.ts'
import { AnchorOid4vpProvider, MemoryAnchorOid4vpStore } from '../../src/anchor/oid4vp.ts'
import { createBisetLoginPresentation, p256PublicJwk } from '../../src/oid4vp/profile.ts'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'

describe('Anchor OID4VP login flow', () => {
  const generation = `1-${'a'.repeat(32)}`
  test('turns a holder-bound login credential into an Anchor session and resumes OIDC once', async () => {
    const now = new Date('2026-08-28T09:00:00.000Z')
    const store = new MemoryAnchorOid4vpStore()
    const holderPrivateKey = new Uint8Array(32).fill(22)
    const oid4vp = new AnchorOid4vpProvider({
      issuer: 'https://anchor.biset.md', store,
      credentialSigningPrivateKey: new Uint8Array(32).fill(21), now: () => now,
    })
    const issued = await oid4vp.issueCredential('anchor-root-account-alice', generation, p256PublicJwk(holderPrivateKey))
    const oidc = new AnchorOidcProvider({
      issuer: 'https://anchor.biset.md',
      clients: [{ clientId: 'biset-client', redirectUris: ['https://biset.md/oauth/callback'], sectorIdentifier: 'biset.md', audience: 'https://coordinator.biset.md', allowedScopes: ['vault.pull'] }],
      authenticator: oid4vp, codes: new MemoryAnchorAuthorizationCodeStore(),
      signingPrivateKey: new Uint8Array(32).fill(23), pairwiseSecret: new Uint8Array(32).fill(24), now: () => now,
    })
    const directory = mkdtempSync(join(tmpdir(), 'anchor-oid4vp-flow-'))
    const anchor = createBisetAnchorDeployment({ dataDir: directory, oidc, oid4vp })
    try {
      const verifier = 'p'.repeat(43)
      const authorizeUrl = new URL('https://anchor.biset.md/oauth/authorize')
      for (const [key, value] of Object.entries({
        response_type: 'code', client_id: 'biset-client', redirect_uri: 'https://biset.md/oauth/callback',
        scope: 'openid vault.pull', state: 'outer-state', nonce: 'outer-nonce',
        code_challenge: bytesToBase64url(sha256(new TextEncoder().encode(verifier))), code_challenge_method: 'S256', wallet_origin: 'null',
      })) authorizeUrl.searchParams.set(key, value)

      const loginStart = await anchor.fetch(new Request(authorizeUrl))
      expect(loginStart.status).toBe(302)
      const walletInvocation = new URL(loginStart.headers.get('location')!)
      expect(walletInvocation.origin + walletInvocation.pathname).toBe('https://anchor.biset.md/oid4vp/wallet-bridge')
      expect(walletInvocation.searchParams.get('bridge_nonce')).toHaveLength(32)
      const requestUri = walletInvocation.searchParams.get('request_uri')!

      const requestObjectResponse = await anchor.fetch(new Request(requestUri))
      expect(requestObjectResponse.status).toBe(200)
      const requestObject = await requestObjectResponse.json() as { client_id: string; response_uri: string; nonce: string; state: string; response_mode: string }
      expect(requestObject).toMatchObject({ response_mode: 'direct_post', client_id: 'https://anchor.biset.md/oid4vp/response' })
      const presentation = createBisetLoginPresentation({
        credential: issued.credential, holderPrivateKey,
        verifierId: requestObject.client_id, nonce: requestObject.nonce, now,
      })
      const directPostForm = new URLSearchParams({ vp_token: presentation, state: requestObject.state })
      const directPost = await anchor.fetch(new Request(requestObject.response_uri, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: directPostForm,
      }))
      expect(directPost.status).toBe(200)
      const { redirect_uri: completionUri } = await directPost.json() as { redirect_uri: string }

      const replayPresentation = await anchor.fetch(new Request(requestObject.response_uri, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: directPostForm,
      }))
      expect(replayPresentation.status).toBe(400)

      const completion = await anchor.fetch(new Request(completionUri))
      expect(completion.status).toBe(302)
      expect(completion.headers.get('location')).toBe(authorizeUrl.href)
      const setCookie = completion.headers.get('set-cookie')!
      expect(setCookie).toContain('HttpOnly')
      expect(setCookie).toContain('SameSite=Lax')
      const cookie = setCookie.split(';', 1)[0]!

      const resumed = await anchor.fetch(new Request(completion.headers.get('location')!, { headers: { cookie } }))
      expect(resumed.status).toBe(302)
      const callback = new URL(resumed.headers.get('location')!)
      expect(callback.origin + callback.pathname).toBe('https://biset.md/oauth/callback')
      expect(callback.searchParams.get('code')).toBeTruthy()

      const completionReplay = await anchor.fetch(new Request(completionUri))
      expect(completionReplay.status).toBe(400)
    } finally {
      rmSync(directory, { recursive: true, force: true })
    }
  })

  test('rejects a presentation after the login credential is revoked', async () => {
    const now = new Date('2026-08-28T09:00:00.000Z')
    const store = new MemoryAnchorOid4vpStore()
    const holderPrivateKey = p256.utils.randomSecretKey()
    const oid4vp = new AnchorOid4vpProvider({ issuer: 'https://anchor.biset.md', store, credentialSigningPrivateKey: p256.utils.randomSecretKey(), now: () => now })
    const issued = await oid4vp.issueCredential('root-account', generation, p256PublicJwk(holderPrivateKey))
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(issued.credential.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')), value => value.charCodeAt(0)))) as { id: string }
    expect(await oid4vp.revokeCredential(payload.id)).toBe(true)

    const start = await oid4vp.beginAuthentication(new Request('https://anchor.biset.md/oauth/authorize?client_id=x&wallet_origin=null'))
    const requestUri = new URL(start.headers.get('location')!).searchParams.get('request_uri')!
    const request = await (await oid4vp.requestObject(requestUri.split('/').pop()!)).json() as { client_id: string; response_uri: string; nonce: string; state: string }
    const presentation = createBisetLoginPresentation({ credential: issued.credential, holderPrivateKey, verifierId: request.client_id, nonce: request.nonce, now })
    const response = await oid4vp.directPost(new Request(request.response_uri, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ state: request.state, vp_token: presentation }) }))
    expect(response.status).toBe(400)
    expect(await response.json()).toEqual({ error: 'invalid_vp_token' })
  })

  test('issuing a new Sign generation revokes older credentials and sessions', async () => {
    const now = new Date('2026-08-28T09:00:00.000Z')
    const store = new MemoryAnchorOid4vpStore()
    const oid4vp = new AnchorOid4vpProvider({ issuer: 'https://anchor.biset.md', store, credentialSigningPrivateKey: p256.utils.randomSecretKey(), now: () => now })
    const old = await oid4vp.issueCredential('root-account', `1-${'a'.repeat(32)}`, p256PublicJwk(p256.utils.randomSecretKey()))
    const oldId = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(old.credential.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')), value => value.charCodeAt(0)))).id as string
    await store.putSession({ sessionHash: 'old-session', rootSubject: 'root-account', generation: `1-${'a'.repeat(32)}`, authenticatedAt: 1, expiresAt: 9999999999 })

    await oid4vp.issueCredential('root-account', `2-${'b'.repeat(32)}`, p256PublicJwk(p256.utils.randomSecretKey()))

    expect((await store.credential(oldId))?.revokedAt).toBe(Math.floor(now.getTime() / 1000))
    expect(await store.session('old-session')).toBeUndefined()
  })
})
