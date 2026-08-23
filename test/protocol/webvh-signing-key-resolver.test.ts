// Exercises the read-only did:webvh resolver (src/identity/webvh/) and the
// DeviceSigningPublicKeyResolver it backs (WebvhSigningKeyResolver), against
// a hand-built signed log — no anchor server needed.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { resolveEntries, WebvhResolutionError } from '../../src/identity/webvh/resolver.ts'
import { WebvhSigningKeyResolver } from '../../src/core/identity/webvh-signing-key-resolver.ts'
import { buildGenesisLog, signProof, withFetch } from './support/webvh-log-fixture.ts'

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
  test('resolves the device key listed in verificationMethod', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const devicePrivateKey = ed25519.utils.randomSecretKey()
    const devicePublicKey = ed25519.getPublicKey(devicePrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [{ fragment: 'device-a', publicKey: devicePublicKey }])

    await withFetch(log, async () => {
      const resolver = new WebvhSigningKeyResolver()
      const resolved = await resolver.resolveEd25519PublicKey(`${did}#device-a`)
      expect(resolved).toEqual(devicePublicKey)
    })
  })

  test('fails closed on an unlisted fragment', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])

    await withFetch(log, async () => {
      const resolver = new WebvhSigningKeyResolver()
      expect(await resolver.resolveEd25519PublicKey(`${did}#device-a`)).toBeUndefined()
    })
  })

  test('fails closed when the DID has no log', async () => {
    await withFetch(null, async () => {
      const resolver = new WebvhSigningKeyResolver()
      expect(await resolver.resolveEd25519PublicKey('did:webvh:deadbeef:test.example#device-a')).toBeUndefined()
    })
  })

  test('fails closed on a malformed signing key id (no fragment)', async () => {
    const resolver = new WebvhSigningKeyResolver()
    expect(await resolver.resolveEd25519PublicKey('did:webvh:deadbeef:test.example')).toBeUndefined()
  })

  test('fails closed when the log fails verification', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [{ fragment: 'device-a', publicKey: ed25519.getPublicKey(ed25519.utils.randomSecretKey()) }])
    const tampered = [{ ...log[0]!, state: { ...log[0]!.state, name: 'injected' } }]

    await withFetch(tampered, async () => {
      const resolver = new WebvhSigningKeyResolver()
      expect(await resolver.resolveEd25519PublicKey(`${did}#device-a`)).toBeUndefined()
    })
  })
})
