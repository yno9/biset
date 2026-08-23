// createGenesis + addDeviceVerificationMethod + resolve, end to end: a
// second device's MLS leaf key becomes resolvable exactly the way
// Ed25519MlsDsSignatureVerifier / WebvhSigningKeyResolver need it to be.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { addDeviceVerificationMethod } from '../../src/identity/webvh/add-device-verification-method.ts'
import { resolve } from '../../src/identity/webvh/resolver.ts'
import { decodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'

describe('addDeviceVerificationMethod', () => {
  test('registers a device key that the resolver then returns alongside the root key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const devicePrivateKey = ed25519.utils.randomSecretKey()
    const devicePublicKey = ed25519.getPublicKey(devicePrivateKey)
    const anchor = fakeAnchor()

    const { did } = await createGenesis({ domain: 'test.example', pathSegments: ['alice'], rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    await addDeviceVerificationMethod({ did, fragment: 'device-a', devicePublicKey, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, fetch: anchor.fetch })

    const realFetch = globalThis.fetch
    globalThis.fetch = anchor.fetch
    try {
      const doc = await resolve(did)
      expect(doc?.verificationMethod).toHaveLength(2)
      const deviceVm = doc?.verificationMethod.find(vm => vm.id === `${did}#device-a`)
      expect(deviceVm).toBeDefined()
      expect(decodeMultikey(deviceVm!.publicKeyMultibase)).toEqual(devicePublicKey)
      // The root key entry survives untouched.
      expect(decodeMultikey(doc!.verificationMethod[0]!.publicKeyMultibase)).toEqual(rootPublicKey)
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('is idempotent: registering the same fragment twice does not append a second log entry', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const devicePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const anchor = fakeAnchor()

    const { did } = await createGenesis({ domain: 'test.example', pathSegments: ['alice'], rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    await addDeviceVerificationMethod({ did, fragment: 'device-a', devicePublicKey, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, fetch: anchor.fetch })
    await addDeviceVerificationMethod({ did, fragment: 'device-a', devicePublicKey, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, fetch: anchor.fetch })

    const realFetch = globalThis.fetch
    globalThis.fetch = anchor.fetch
    try {
      const doc = await resolve(did)
      expect(doc?.verificationMethod).toHaveLength(2)
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('rejects a signing key not authorized by the document\'s current updateKeys', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const strangerPrivateKey = ed25519.utils.randomSecretKey()
    const strangerPublicKey = ed25519.getPublicKey(strangerPrivateKey)
    const devicePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const anchor = fakeAnchor()

    const { did } = await createGenesis({ domain: 'test.example', pathSegments: ['alice'], rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    await expect(addDeviceVerificationMethod({
      did, fragment: 'device-a', devicePublicKey, signingPrivateKey: strangerPrivateKey, signingPublicKey: strangerPublicKey, fetch: anchor.fetch,
    })).rejects.toThrow('not authorized')
  })
})
