import 'fake-indexeddb/auto'
import { afterEach, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { resolveWalletFromSuffix } from '../../src/client/identity/wallet/did-md-oauth.ts'
import { jcsMultihashBase58, signProof, encodeMultikey } from '../protocol/support/webvh-log-fixture.ts'

// Wallet discovery by did:webvh suffix (atproto-style: resolve the
// identity's own DID document, read its "UDIWalletIssuer" service entry --
// the same pattern atproto's #atproto_pds/AtprotoPersonalDataServer entry
// uses for PDS discovery, applied to wallet discovery instead of data
// hosting). See ~/did.md/client/did-webvh.ts's buildGenesis, which publishes
// this entry, and ~/did.md/ARC.md §3.4 / §4.4 for the design rationale.

function genesisLog(domain: string, service: Array<{ id: string; type: string; serviceEndpoint: string }>) {
  const privateKey = ed25519.utils.randomSecretKey()
  const publicKey = ed25519.getPublicKey(privateKey)
  const updateKey = encodeMultikey(publicKey)
  const versionTime = '2026-09-21T00:00:00.000Z'
  const placeholderDid = `did:webvh:{SCID}:${domain}`
  const parameters = { method: 'did:webvh:1.0', scid: '{SCID}', updateKeys: [updateKey], nextKeyHashes: [], portable: false, witness: {}, watchers: [], deactivated: false, ttl: 3600 }
  const rootKeyId = `${placeholderDid}#pass-1`
  const state = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: placeholderDid,
    verificationMethod: [{ id: rootKeyId, type: 'Multikey' as const, controller: placeholderDid, publicKeyMultibase: updateKey }],
    authentication: [rootKeyId],
    service: service.map(entry => ({ id: `${placeholderDid}${entry.id}`, type: entry.type, serviceEndpoint: entry.serviceEndpoint })),
  }
  const preliminary = { versionId: '{SCID}', versionTime, parameters, state }
  const scid = jcsMultihashBase58(preliminary)
  const did = placeholderDid.replace('{SCID}', scid)
  const real = JSON.parse(JSON.stringify({ parameters, state }).split('{SCID}').join(scid)) as { parameters: typeof parameters; state: typeof state }
  const entryHash = jcsMultihashBase58({ versionId: scid, versionTime, parameters: real.parameters, state: real.state })
  const versionId = `1-${entryHash}`
  const unsigned = { versionId, versionTime, parameters: real.parameters, state: real.state }
  const proof = signProof(unsigned, `did:key:${updateKey}#${updateKey}`, privateKey, versionTime)
  return { did, log: [{ ...unsigned, proof: [proof] }] }
}

const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })

test('resolveWalletFromSuffix reads the UDIWalletIssuer service entry and completes discovery', async () => {
  const { log } = genesisLog('alice.did.md', [{ id: '#udi-wallet-issuer', type: 'UDIWalletIssuer', serviceEndpoint: 'https://api.did.md' }])
  const requested: string[] = []
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = input.toString()
    requested.push(url)
    if (url === 'https://alice.did.md/.well-known/did.jsonl') return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n', { status: 200 })
    if (url === 'https://api.did.md/.well-known/oauth-authorization-server') {
      return Response.json({ issuer: 'https://api.did.md', authorization_endpoint: 'https://app.did.md/authorize', token_endpoint: 'https://api.did.md/v1/oauth/token', registration_endpoint: 'https://api.did.md/v1/oauth/register' })
    }
    return new Response('not found', { status: 404 })
  }) as typeof fetch

  const entry = await resolveWalletFromSuffix('alice.did.md')
  expect(entry).toEqual({ id: 'suffix:alice.did.md', displayName: 'alice.did.md', issuer: 'https://api.did.md', handleSuffix: '.alice.did.md' })
  expect(requested).toEqual(['https://alice.did.md/.well-known/did.jsonl', 'https://api.did.md/.well-known/oauth-authorization-server'])
})

test('resolveWalletFromSuffix rejects a domain with no did:webvh identity', async () => {
  globalThis.fetch = (async () => new Response('not found', { status: 404 })) as typeof fetch
  await expect(resolveWalletFromSuffix('nobody.example')).rejects.toThrow(/no did:webvh identity/)
})

test('resolveWalletFromSuffix rejects an identity that does not publish a wallet', async () => {
  const { log } = genesisLog('bob.did.md', [])
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    if (input.toString() === 'https://bob.did.md/.well-known/did.jsonl') return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n', { status: 200 })
    return new Response('not found', { status: 404 })
  }) as typeof fetch
  await expect(resolveWalletFromSuffix('bob.did.md')).rejects.toThrow(/does not publish a wallet/)
})

test('resolveWalletFromSuffix rejects a malformed suffix before any network call', async () => {
  globalThis.fetch = (async () => { throw new Error('must not fetch'); }) as typeof fetch
  await expect(resolveWalletFromSuffix('not a domain')).rejects.toThrow(/Enter a domain/)
})
