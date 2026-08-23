// Verifies the Authentication Service role (RFC 9750 §4): an MLS leaf's
// credential must name a verificationMethod entry whose key equals the
// leaf's ACTUAL signature key (mls/webvh-authentication-service.ts), not
// merely a listed device id (the pre-rewrite check).
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { generateOwnKeyPackage } from '../../src/mls/group.ts'
import { credentialFor } from '../../src/mls/identity.ts'
import { webvhAuthenticationService } from '../../src/mls/webvh-authentication-service.ts'
import { buildGenesisLog, withFetch } from './support/webvh-log-fixture.ts'

describe('webvh Authentication Service', () => {
  test('accepts a credential whose verificationMethod key matches the leaf signature key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const own = await generateOwnKeyPackage('did:webvh:{SCID}:test.example#device-a')
    const leafSignaturePublicKey = own.publicPackage.leafNode.signaturePublicKey

    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [{ fragment: 'device-a', publicKey: leafSignaturePublicKey }])
    const credential = credentialFor(`${did}#device-a`)

    await withFetch(log, async () => {
      expect(await webvhAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(true)
    })
  })

  test('rejects when the verificationMethod names a DIFFERENT key than the leaf actually signs with', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const own = await generateOwnKeyPackage('did:webvh:{SCID}:test.example#device-a')
    const leafSignaturePublicKey = own.publicPackage.leafNode.signaturePublicKey
    const impostorPublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())

    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [{ fragment: 'device-a', publicKey: impostorPublicKey }])
    const credential = credentialFor(`${did}#device-a`)

    await withFetch(log, async () => {
      expect(await webvhAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(false)
    })
  })

  test('fails closed when the fragment is not listed at all', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const own = await generateOwnKeyPackage('did:webvh:{SCID}:test.example#device-a')
    const leafSignaturePublicKey = own.publicPackage.leafNode.signaturePublicKey

    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = credentialFor(`${did}#device-a`)

    await withFetch(log, async () => {
      expect(await webvhAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(false)
    })
  })

  test('fails closed when the DID cannot be resolved', async () => {
    const own = await generateOwnKeyPackage('did:webvh:deadbeef:test.example#device-a')
    const credential = credentialFor('did:webvh:deadbeef:test.example#device-a')
    await withFetch(null, async () => {
      expect(await webvhAuthenticationService.validateCredential(credential, own.publicPackage.leafNode.signaturePublicKey)).toBe(false)
    })
  })

  test('rejects a non-basic / non-DID-URL credential without resolving anything', async () => {
    expect(await webvhAuthenticationService.validateCredential({ credentialType: 'x509', certificates: [] }, new Uint8Array(32))).toBe(false)
  })
})
