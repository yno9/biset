// buildRoutingDoc's MimiDeliveryService entry (PLAN_biset-mls-ds.md §11-7),
// resolved end-to-end the same way resolveDidCommSenderKey resolves a
// DIDComm keyAgreement key -- DID resolve -> routing.json fetch -> merged
// document, so a caller can discover this identity's Conversation Group DS
// directly, no DIDComm mediator relay needed.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { encodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { multikeyHashBase58 } from '../../src/identity/webvh/hash.ts'
import { buildRoutingDoc, putRouting } from '../../src/didcomm/webvh-routing.ts'
import { resolveMimiProviderUrl } from '../../src/didcomm/webvh-resolve.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'

describe('resolveMimiProviderUrl', () => {
  test('resolves a published MimiDeliveryService endpoint from the DID document', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const anchor = fakeAnchor()
    const rootSigning = { updateKey: encodeMultikey(rootPublicKey), privateKey: rootPrivateKey }
    const nextSparePrivateKey = ed25519.utils.randomSecretKey()
    const nextKeyHash = multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(nextSparePrivateKey)))

    const { did } = await createGenesis({ domain: 'mimi-provider.example', rootPrivateKey, rootPublicKey, nextKeyHash, fetch: anchor.fetch })
    await putRouting(did, buildRoutingDoc(did, { mimiProvider: { url: 'https://mls-ds.mimi-provider.example' } }), rootSigning, anchor.fetch)

    const realFetch = globalThis.fetch
    globalThis.fetch = anchor.fetch
    try {
      expect(await resolveMimiProviderUrl(did, anchor.fetch)).toBe('https://mls-ds.mimi-provider.example')
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('returns undefined for an identity with no registered Conversation Group DS', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const anchor = fakeAnchor()
    const rootSigning = { updateKey: encodeMultikey(rootPublicKey), privateKey: rootPrivateKey }
    const nextSparePrivateKey = ed25519.utils.randomSecretKey()
    const nextKeyHash = multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(nextSparePrivateKey)))

    const { did } = await createGenesis({ domain: 'no-mimi.example', rootPrivateKey, rootPublicKey, nextKeyHash, fetch: anchor.fetch })
    await putRouting(did, buildRoutingDoc(did, { didCommEndpoint: 'https://core.no-mimi.example/v1/didcomm/ingress' }), rootSigning, anchor.fetch)

    const realFetch = globalThis.fetch
    globalThis.fetch = anchor.fetch
    try {
      expect(await resolveMimiProviderUrl(did, anchor.fetch)).toBeUndefined()
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
