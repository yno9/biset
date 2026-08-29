// Verifies the Authentication Service role (RFC 9750 §4): an MLS leaf's
// credential must be signed by the stable Root Key in the DID document and
// bind the leaf's ACTUAL signature key.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { credentialFor } from '../../src/mls/identity.ts'
import { createMlsDeviceCredential } from '../../src/mls/device-credential.ts'
import { webvhAuthenticationService } from '../../src/mls/webvh-authentication-service.ts'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { migrateWebvhLocation } from '../../src/identity/webvh/migrate.ts'
import { buildGenesisLog, fakeAnchor, withFetch } from './support/webvh-log-fixture.ts'

describe('webvh Authentication Service', () => {
  test('accepts a Root-signed credential whose embedded key matches the leaf signature key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = credentialFor(createMlsDeviceCredential(did, leafSignaturePublicKey, rootPrivateKey))

    await withFetch(log, async () => {
      expect(await webvhAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(true)
    })
  })

  test('rejects when the embedded key differs from the leaf key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const impostorPublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = credentialFor(createMlsDeviceCredential(did, impostorPublicKey, rootPrivateKey))

    await withFetch(log, async () => {
      expect(await webvhAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(false)
    })
  })

  test('fails closed when the credential was signed by a different Root Key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = credentialFor(createMlsDeviceCredential(did, leafSignaturePublicKey, ed25519.utils.randomSecretKey()))

    await withFetch(log, async () => {
      expect(await webvhAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(false)
    })
  })

  test('fails closed when the DID cannot be resolved', async () => {
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const credential = credentialFor(createMlsDeviceCredential('did:webvh:deadbeef:test.example', leafSignaturePublicKey, ed25519.utils.randomSecretKey()))
    await withFetch(null, async () => {
      expect(await webvhAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(false)
    })
  })

  test('rejects a non-basic / non-DID-URL credential without resolving anything', async () => {
    expect(await webvhAuthenticationService.validateCredential({ credentialType: 'x509', certificates: [] }, new Uint8Array(32))).toBe(false)
  })

  // Root-cause regression guard: `validateRatchetTree` (vendor/clientState.ts)
  // re-validates EVERY leaf's credential -- not just a changed one -- on a
  // new device's join. A device that never re-issued its own credential
  // (never moved) must keep validating under its OWN unchanged (old-did
  // -prefixed) credential after a SIBLING device moves, or every future
  // join to the self-group would fail the moment ANY device has moved.
  test('a never-moved device\'s unchanged credential still validates after the identity moves', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const anchor = fakeAnchor()

    const { did: oldDid } = await createGenesis({ domain: 'move-src.example', rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    const credential = credentialFor(createMlsDeviceCredential(oldDid, leafSignaturePublicKey, rootPrivateKey))

    // Someone else's move: only the domain changes, device-b never re-issues its credential.
    await migrateWebvhLocation({
      oldDid, newDomain: 'move-dst.example', signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, fetch: anchor.fetch,
    })

    const realFetch = globalThis.fetch
    globalThis.fetch = anchor.fetch
    try {
      expect(await webvhAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(true)
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
