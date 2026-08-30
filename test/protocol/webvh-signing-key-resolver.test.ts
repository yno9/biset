// Exercises the read-only did:webvh resolver (src/identity/webvh/) and the
// DeviceSigningPublicKeyResolver it backs (WebvhSigningKeyResolver), against
// a hand-built signed log — no anchor server needed.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { resolveEntries, WebvhResolutionError } from '../../src/identity/webvh/resolver.ts'
import { WebvhSigningKeyResolver } from '../../src/core/identity/webvh-signing-key-resolver.ts'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { migrateWebvhLocation } from '../../src/identity/webvh/migrate.ts'
import { encodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { multikeyHashBase58 } from '../../src/identity/webvh/hash.ts'
import { createMlsDeviceCredential, encodeMlsDeviceCredential } from '../../src/mls/device-credential.ts'
import { buildGenesisLog, fakeAnchor, signProof, withFetch } from './support/webvh-log-fixture.ts'

describe('webvh resolver (read-only)', () => {
  test('resolveEntries verifies SCID, entryHash and proof, and returns every verificationMethod', () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const devicePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [{ fragment: 'device-a', publicKey: devicePublicKey }])

    const doc = resolveEntries(did, log)
    expect(doc?.id).toBe(did)
    expect(doc?.verificationMethod).toHaveLength(2)
    expect(doc?.verificationMethod[1]?.id).toBe(`${did}#device-a`)
  })

  test('resolveEntries rejects a tampered state (entryHash mismatch)', () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const tampered = [{ ...log[0]!, state: { ...log[0]!.state, name: 'injected' } }]
    expect(() => resolveEntries(did, tampered)).toThrow(WebvhResolutionError)
  })

  test('resolveEntries rejects a proof from the wrong key', () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const wrongKey = ed25519.utils.randomSecretKey()
    const rebuilt = { ...log[0]!, proof: [signProof({ versionId: log[0]!.versionId, versionTime: log[0]!.versionTime, parameters: log[0]!.parameters, state: log[0]!.state }, log[0]!.proof[0]!.verificationMethod, wrongKey, log[0]!.versionTime)] }
    expect(() => resolveEntries(did, [rebuilt])).toThrow(WebvhResolutionError)
  })
})

describe('WebvhSigningKeyResolver (DeviceSigningPublicKeyResolver)', () => {
  test('resolves a Root-signed device credential without a device verificationMethod', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const devicePrivateKey = ed25519.utils.randomSecretKey()
    const devicePublicKey = ed25519.getPublicKey(devicePrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = createMlsDeviceCredential(did, devicePublicKey, rootPrivateKey)

    await withFetch(log, async () => {
      const resolver = new WebvhSigningKeyResolver()
      const resolved = await resolver.resolveEd25519PublicKey(credential.deviceKid, did, encodeMlsDeviceCredential(credential))
      expect(resolved).toEqual(devicePublicKey)
    })
  })

  test('fails closed when the requested kid does not match the credential', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const devicePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = createMlsDeviceCredential(did, devicePublicKey, rootPrivateKey)

    await withFetch(log, async () => {
      const resolver = new WebvhSigningKeyResolver()
      expect(await resolver.resolveEd25519PublicKey(`${did}#wrong`, did, encodeMlsDeviceCredential(credential))).toBeUndefined()
    })
  })

  test('fails closed when the DID has no log', async () => {
    await withFetch(null, async () => {
      const resolver = new WebvhSigningKeyResolver()
      const did = 'did:webvh:deadbeef:test.example'
      const credential = createMlsDeviceCredential(did, ed25519.getPublicKey(ed25519.utils.randomSecretKey()), ed25519.utils.randomSecretKey())
      expect(await resolver.resolveEd25519PublicKey(credential.deviceKid, did, encodeMlsDeviceCredential(credential))).toBeUndefined()
    })
  })

  test('fails closed on a malformed credential', async () => {
    const resolver = new WebvhSigningKeyResolver()
    expect(await resolver.resolveEd25519PublicKey('did:webvh:deadbeef:test.example', 'did:webvh:deadbeef:test.example', new Uint8Array([1]))).toBeUndefined()
  })

  test('fails closed when the log fails verification', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const devicePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const credential = createMlsDeviceCredential(did, devicePublicKey, rootPrivateKey)
    const tampered = [{ ...log[0]!, state: { ...log[0]!.state, name: 'injected' } }]

    await withFetch(tampered, async () => {
      const resolver = new WebvhSigningKeyResolver()
      expect(await resolver.resolveEd25519PublicKey(credential.deviceKid, did, encodeMlsDeviceCredential(credential))).toBeUndefined()
    })
  })

  // Root-cause regression guard for the multi-device domain-move gap
  // (test/protocol/mls-self-group-move-multidevice.test.ts): a device that
  // never itself moved must keep resolving under its OWN unchanged
  // (old-did-prefixed) kid after a SIBLING device's move rewrites the whole
  // document's id prefix. This is deliberately independent of that MLS-level
  // test — it isolates the resolver's fragment-matching fix from the whole
  // self-group/DS stack.
  test('a never-moved device\'s old kid still resolves after the identity moves', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const deviceBPrivateKey = ed25519.utils.randomSecretKey()
    const deviceBPublicKey = ed25519.getPublicKey(deviceBPrivateKey)
    const anchor = fakeAnchor()
    const currentSparePrivateKey = ed25519.utils.randomSecretKey()
    const currentSparePublicKey = ed25519.getPublicKey(currentSparePrivateKey)
    const currentSpareHash = multikeyHashBase58(encodeMultikey(currentSparePublicKey))

    const { did: oldDid } = await createGenesis({
      domain: 'move-src.example', rootPrivateKey, rootPublicKey,
      nextKeyHash: currentSpareHash, fetch: anchor.fetch,
    })
    const credential = createMlsDeviceCredential(oldDid, deviceBPublicKey, rootPrivateKey)
    const deviceBKid = credential.deviceKid

    // Someone else's move: only the domain changes, device-b never re-publishes.
    const nextSparePrivateKey = ed25519.utils.randomSecretKey()
    const nextKeyHash = multikeyHashBase58(encodeMultikey(ed25519.getPublicKey(nextSparePrivateKey)))
    await migrateWebvhLocation({
      oldDid, newDomain: 'move-dst.example',
      signingPrivateKey: currentSparePrivateKey, signingPublicKey: currentSparePublicKey,
      nextKeyHash, fetch: anchor.fetch,
    })

    const realFetch = globalThis.fetch
    globalThis.fetch = anchor.fetch
    try {
      const resolver = new WebvhSigningKeyResolver()
      // Never resolved before -- proves this isn't just the cache papering
      // over a live-resolution failure, but a genuinely correct first resolve.
      expect(await resolver.resolveEd25519PublicKey(deviceBKid, oldDid, encodeMlsDeviceCredential(credential))).toEqual(deviceBPublicKey)
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
