import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { p256 } from '@noble/curves/nist.js'
import { AnchorOid4vpProvider, MemoryAnchorOid4vpStore } from '../../src/anchor/oid4vp.ts'
import { p256PublicJwk } from '../../src/oid4vp/profile.ts'
import { BisetOid4vpWallet } from '../../src/oid4vp/wallet.ts'
import { IndexedDbBisetLoginWalletCredentialStore } from '../../src/oid4vp/wallet-store.ts'

const databaseName = 'biset-wallet-oid4vp-test'
afterEach(async () => {
  await new Promise<void>(resolve => {
    const request = indexedDB.deleteDatabase(databaseName)
    request.onsuccess = () => resolve()
    request.onerror = () => resolve()
    request.onblocked = () => resolve()
  })
})

describe('Biset OID4VP Wallet', () => {
  const generation = `1-${'a'.repeat(32)}`
  test('verifies, persists, presents, and rekeys a device-local Anchor credential', async () => {
    const now = new Date('2026-08-28T10:00:00.000Z')
    const issuerPrivateKey = new Uint8Array(32).fill(31)
    const holderPrivateKey = new Uint8Array(32).fill(32)
    const anchor = new AnchorOid4vpProvider({ issuer: 'https://anchor.biset.md', store: new MemoryAnchorOid4vpStore(), credentialSigningPrivateKey: issuerPrivateKey, now: () => now })
    const issued = await anchor.issueCredential('root-subject', generation, p256PublicJwk(holderPrivateKey))
    const state = new IndexedDbBisetLoginWalletCredentialStore(databaseName)
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const path = new URL(request.url).pathname
      if (path.startsWith('/oid4vp/request/')) return anchor.requestObject(path.split('/').pop()!)
      if (path === '/oid4vp/response') return anchor.directPost(request)
      return new Response('not found', { status: 404 })
    }) as typeof fetch
    const wallet = new BisetOid4vpWallet({
      identityId: 'did:webvh:old:old.biset.md',
      generation,
      trust: {
        issuer: 'https://anchor.biset.md',
        credentialSigningKeyId: 'https://anchor.biset.md/oid4vp/jwks#login-credential-es256-1',
        credentialSigningPublicKey: p256PublicJwk(issuerPrivateKey),
      },
      store: state,
      now: () => now,
      fetch: fetchImpl,
    })
    const installed = await wallet.install(issued.credential, holderPrivateKey)
    state.close()

    const reopened = new IndexedDbBisetLoginWalletCredentialStore(databaseName)
    expect((await reopened.current('did:webvh:old:old.biset.md', 'https://anchor.biset.md', now))?.credentialId).toBe(installed.credentialId)
    await reopened.rekeyIdentity('did:webvh:old:old.biset.md', 'did:webvh:new:new.biset.md')
    expect(await reopened.current('did:webvh:old:old.biset.md', 'https://anchor.biset.md', now)).toBeUndefined()
    expect((await reopened.current('did:webvh:new:new.biset.md', 'https://anchor.biset.md', now))?.holderPrivateKey).toEqual(holderPrivateKey)
    reopened.close()

    const movedWalletStore = new IndexedDbBisetLoginWalletCredentialStore(databaseName)
    const movedWallet = new BisetOid4vpWallet({
      identityId: 'did:webvh:new:new.biset.md',
      generation,
      trust: {
        issuer: 'https://anchor.biset.md', credentialSigningKeyId: 'https://anchor.biset.md/oid4vp/jwks#login-credential-es256-1', credentialSigningPublicKey: p256PublicJwk(issuerPrivateKey),
      }, store: movedWalletStore, now: () => now,
      fetch: fetchImpl,
    })
    const login = await anchor.beginAuthentication(new Request('https://anchor.biset.md/oauth/authorize?client_id=biset-client&wallet_origin=null'))
    const requestUri = new URL(login.headers.get('location')!).searchParams.get('request_uri')!
    const completionUri = await movedWallet.respond(requestUri)
    expect(completionUri).toStartWith('https://anchor.biset.md/oid4vp/complete?response_code=')
    movedWalletStore.close()
  })

  test('rejects an untrusted request URI and a credential bound to another holder', async () => {
    const now = new Date('2026-08-28T10:00:00.000Z')
    const issuerPrivateKey = p256.utils.randomSecretKey()
    const holderPrivateKey = p256.utils.randomSecretKey()
    const anchor = new AnchorOid4vpProvider({ issuer: 'https://anchor.biset.md', store: new MemoryAnchorOid4vpStore(), credentialSigningPrivateKey: issuerPrivateKey, now: () => now })
    const issued = await anchor.issueCredential('root', generation, p256PublicJwk(holderPrivateKey))
    const store = new IndexedDbBisetLoginWalletCredentialStore(databaseName)
    const wallet = new BisetOid4vpWallet({
      identityId: 'identity',
      generation,
      trust: { issuer: 'https://anchor.biset.md', credentialSigningKeyId: 'https://anchor.biset.md/oid4vp/jwks#login-credential-es256-1', credentialSigningPublicKey: p256PublicJwk(issuerPrivateKey) },
      store, now: () => now,
    })
    await expect(wallet.install(issued.credential, p256.utils.randomSecretKey())).rejects.toThrow('another holder key')
    await expect(wallet.respond('https://evil.example/oid4vp/request/value')).rejects.toThrow('not trusted')
    store.close()
  })
})
