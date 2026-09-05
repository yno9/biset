// Root-cause regression guard for the DIDComm-side counterpart of the same
// domain-move bug fixed in core/identity/webvh-signing-key-resolver.ts and
// mls/webvh-authentication-service.ts: a device that never itself moved
// must keep resolving under its OWN unchanged (old-did-prefixed) DIDComm
// senderKid after a SIBLING device moves the shared identity's domain.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../src/client/identity/webvh/create-genesis.ts'
import { migrateWebvhLocation } from '../../src/client/identity/webvh/migrate.ts'
import { encodeMultikey } from '../../src/client/identity/webvh/multikey.ts'
import { multikeyHashBase58 } from '../../src/client/identity/webvh/hash.ts'
import { buildRoutingDoc, fetchRouting, putRouting } from '../../src/shared/didcomm/webvh-routing.ts'
import { resolveDidCommSenderKey } from '../../src/shared/didcomm/webvh-resolve.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'

describe('resolveDidCommSenderKey', () => {
  test('a never-moved device\'s senderKid still resolves after the identity moves', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const senderPrivateKey = x25519.utils.randomSecretKey()
    const senderPublicKey = x25519.getPublicKey(senderPrivateKey)
    const anchor = fakeAnchor()
    const rootSigning = { updateKey: encodeMultikey(rootPublicKey), privateKey: rootPrivateKey }
    const currentSparePrivateKey = ed25519.utils.randomSecretKey()
    const currentSparePublicKey = ed25519.getPublicKey(currentSparePrivateKey)
    const currentSpareHash = multikeyHashBase58(encodeMultikey(currentSparePublicKey))

    const { did: oldDid } = await createGenesis({
      domain: 'move-src.example', rootPrivateKey, rootPublicKey,
      nextKeyHash: currentSpareHash, fetch: anchor.fetch,
    })
    const senderKid = `${oldDid}#k1`
    await putRouting(oldDid, buildRoutingDoc(oldDid, { keyAgreementKeys: [{ kid: '#k1', publicKey: senderPublicKey }] }), rootSigning, anchor.fetch)

    // Someone else's move: only the domain changes, this sender device never re-publishes.
    const nextSparePrivateKey = ed25519.utils.randomSecretKey()
    const nextKeyHash = multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(nextSparePrivateKey)))
    const { newDid } = await migrateWebvhLocation({
      oldDid, newDomain: 'move-dst.example',
      signingPrivateKey: currentSparePrivateKey, signingPublicKey: currentSparePublicKey,
      nextKeyHash, fetch: anchor.fetch,
    })
    // Carries routing.json the same way identity/webvh/move.ts's own
    // afterNewLocationWritten hook does -- whole-document string substitution.
    const currentRouting = await fetchRouting(oldDid, anchor.fetch)
    const carried = JSON.parse(JSON.stringify(currentRouting).split(oldDid).join(newDid))
    await putRouting(newDid, carried, { updateKey: encodeMultikey(currentSparePublicKey), privateKey: currentSparePrivateKey }, anchor.fetch)

    // resolveWithRouting's own resolve() half always uses the real global
    // fetch (identity/webvh/resolver.ts's resolve() takes no fetch
    // override) -- only its routing.json half honors the passed fetchImpl.
    const realFetch = globalThis.fetch
    globalThis.fetch = anchor.fetch
    try {
      expect(await resolveDidCommSenderKey(senderKid, anchor.fetch)).toEqual(senderPublicKey)
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
