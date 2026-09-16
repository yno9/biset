// Root-cause regression guard for the DIDComm-side counterpart of the same
// domain-move bug fixed in core/identity/webvh-signing-key-resolver.ts and
// mls/webvh-authentication-service.ts: a device that never itself moved
// must keep resolving under its OWN unchanged (old-did-prefixed) DIDComm
// senderKid after a SIBLING device moves the shared identity's domain.
//
// The device's X25519 key is published IN the signed log (routing.json was
// retired 2026-09-16), so the move carries it automatically -- migrate.ts's
// whole-document string substitution rewrites the DID prefix on every id,
// never the `#fragment`, which is exactly what the resolver must match on.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { migrateWebvhLocation } from '../../src/client/identity/webvh/migrate.ts'
import { didToHttpsUrl } from '../../src/protocol/webvh/identifier.ts'
import { serializeLog } from '../../src/protocol/webvh/log.ts'
import { encodeMultikey } from '../../src/protocol/webvh/multikey.ts'
import { multikeyHashBase58 } from '../../src/protocol/webvh/hash.ts'
import { resolveDidCommSenderKey } from '../../src/protocol/didcomm/webvh-resolve.ts'
import { buildDidCommLog, fakeAnchor } from './support/webvh-log-fixture.ts'

describe('resolveDidCommSenderKey', () => {
  test('a never-moved device\'s senderKid still resolves after the identity moves', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const senderPrivateKey = x25519.utils.randomSecretKey()
    const senderPublicKey = x25519.getPublicKey(senderPrivateKey)
    const anchor = fakeAnchor()
    const currentSparePrivateKey = ed25519.utils.randomSecretKey()
    const currentSparePublicKey = ed25519.getPublicKey(currentSparePrivateKey)
    const currentSpareHash = multikeyHashBase58(encodeMultikey(currentSparePublicKey))

    const { did: oldDid, log } = buildDidCommLog({
      rootPrivateKey, rootPublicKey,
      keyAgreementKeys: [{ fragment: 'k1', x25519PublicKey: senderPublicKey }],
      endpointUri: 'https://mediator.test.example',
      domain: 'move-src.example',
      portable: true,
      nextKeyHashes: [currentSpareHash],
    })
    await anchor.fetch(didToHttpsUrl(oldDid), { method: 'PUT', headers: { 'Content-Type': 'text/jsonl' }, body: serializeLog(log) })
    const senderKid = `${oldDid}#k1`

    // Someone else's move: only the domain changes, this sender device never
    // re-publishes anything of its own.
    const nextSparePrivateKey = ed25519.utils.randomSecretKey()
    const nextKeyHash = multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(nextSparePrivateKey)))
    await migrateWebvhLocation({
      oldDid, newDomain: 'move-dst.example',
      signingPrivateKey: currentSparePrivateKey, signingPublicKey: currentSparePublicKey,
      nextKeyHash, fetch: anchor.fetch,
    })

    expect(await resolveDidCommSenderKey(senderKid, anchor.fetch)).toEqual(senderPublicKey)
  })
})
