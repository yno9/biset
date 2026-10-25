// Verifies the Authentication Service role (RFC 9750 §4): an MLS leaf's
// credential must be signed by the stable Root Key in the DID document and
// bind the leaf's ACTUAL signature key.
import { describe, expect, test } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { credentialFor } from '../../src/client/mls/identity.ts'
import { createMlsDeviceCredential } from '../../src/client/mls/device-credential.ts'
import { didAuthenticationService } from '../../src/client/mls/did-authentication-service.ts'
import { buildGenesisLog, withFetch } from './support/did-log-fixture.ts'
import { extendVhLog } from './support/vh-log-fixture.ts'

describe('did:vh Authentication Service', () => {
  test('accepts a Root-signed credential whose embedded key matches the leaf signature key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = credentialFor(createMlsDeviceCredential(did, log[0]!.versionId, leafSignaturePublicKey, rootPrivateKey, rootPrivateKey))

    await withFetch(log, async () => {
      expect(await didAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(true)
    })
  })

  test('rejects when the embedded key differs from the leaf key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const impostorPublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = credentialFor(createMlsDeviceCredential(did, log[0]!.versionId, impostorPublicKey, rootPrivateKey, rootPrivateKey))

    await withFetch(log, async () => {
      expect(await didAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(false)
    })
  })

  test('fails closed when the credential was signed by a different Root Key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = credentialFor(createMlsDeviceCredential(did, log[0]!.versionId, leafSignaturePublicKey, rootPrivateKey, ed25519.utils.randomSecretKey()))

    await withFetch(log, async () => {
      expect(await didAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(false)
    })
  })

  test('fails closed when the DID cannot be resolved', async () => {
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const authority = ed25519.utils.randomSecretKey()
    const credential = credentialFor(createMlsDeviceCredential(`did:vh:${'Q'.repeat(46)}`, '1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', leafSignaturePublicKey, authority, authority))
    await withFetch(null, async () => {
      expect(await didAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(false)
    })
  })

  test('rejects a non-basic / non-DID-URL credential without resolving anything', async () => {
    expect(await didAuthenticationService.validateCredential({ credentialType: 'x509', certificates: [] }, new Uint8Array(32))).toBe(false)
  })

  // Root-cause regression guard: `validateRatchetTree` (vendor/clientState.ts)
  // re-validates EVERY leaf's credential -- not just a changed one -- on a
  // new device's join. A device that never re-issued its own credential
  // must keep validating under its OWN unchanged credential (it names the
  // version it was issued at) after the DID's log moved on -- a sibling's
  // update, or the log moving to another host -- or every future join to
  // the self-group would fail the moment ANY update was published.
  test('a previously admitted device credential remains valid after a later version of the DID', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafSignaturePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [], 'move-src.example')
    const credential = credentialFor(createMlsDeviceCredential(did, log[0]!.versionId, leafSignaturePublicKey, rootPrivateKey, rootPrivateKey))

    // Someone else's update: the log moves to another host; this device never re-issues its credential.
    const moved = extendVhLog(log, rootPrivateKey, rootPublicKey, state => { state.alsoKnownAs = ['did:web:move-dst.example', `${did}?src=https://move-dst.example`] }, '2026-08-24T00:00:00Z')
    await withFetch(moved, async () => {
      expect(await didAuthenticationService.validateCredential(credential, leafSignaturePublicKey)).toBe(true)
    })
  })
})
