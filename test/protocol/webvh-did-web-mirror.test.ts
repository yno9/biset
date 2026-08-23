// createGenesis / addDeviceVerificationMethod with didWebMirror: true also
// publish a did:web document (no proof, no history) at the same subdomain's
// /.well-known/did.json, kept in sync with whatever did:webvh currently says.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { addDeviceVerificationMethod } from '../../src/identity/webvh/add-device-verification-method.ts'
import { didWebToHttpsUrl, buildWebDid } from '../../src/identity/web/identifier.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'

describe('did:web mirror', () => {
  test('createGenesis with didWebMirror publishes a matching did:web document', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const anchor = fakeAnchor()

    const { did } = await createGenesis({ domain: 'y.test.example', rootPrivateKey, rootPublicKey, didWebMirror: true, fetch: anchor.fetch })

    const webDid = buildWebDid('y.test.example')
    const response = await anchor.fetch(didWebToHttpsUrl(webDid))
    expect(response.status).toBe(200)
    const doc = await response.json() as { id: string; verificationMethod: Array<{ id: string; controller: string }>; authentication: string[] }
    expect(doc.id).toBe(webDid)
    expect(doc.verificationMethod).toHaveLength(1)
    expect(doc.verificationMethod[0]!.id).toBe(`${webDid}#key-1`)
    expect(doc.verificationMethod[0]!.controller).toBe(webDid)
    expect(doc.authentication).toEqual([`${webDid}#key-1`])
    // No did:webvh SCID leaks into the mirror.
    expect(JSON.stringify(doc)).not.toContain(did.split(':')[2])
  })

  test('addDeviceVerificationMethod with didWebMirror re-syncs the mirror to include the new device', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const devicePublicKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const anchor = fakeAnchor()

    const { did } = await createGenesis({ domain: 'y.test.example', rootPrivateKey, rootPublicKey, didWebMirror: true, fetch: anchor.fetch })
    await addDeviceVerificationMethod({ did, fragment: 'device-a', devicePublicKey, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, didWebMirror: true, fetch: anchor.fetch })

    const webDid = buildWebDid('y.test.example')
    const response = await anchor.fetch(didWebToHttpsUrl(webDid))
    const doc = await response.json() as { verificationMethod: Array<{ id: string }> }
    expect(doc.verificationMethod).toHaveLength(2)
    expect(doc.verificationMethod.map(vm => vm.id)).toContain(`${webDid}#device-a`)
  })

  test('createGenesis without didWebMirror never touches did.json', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const anchor = fakeAnchor()

    await createGenesis({ domain: 'y.test.example', rootPrivateKey, rootPublicKey, fetch: anchor.fetch })

    const webDid = buildWebDid('y.test.example')
    const response = await anchor.fetch(didWebToHttpsUrl(webDid))
    expect(response.status).toBe(404)
  })
})
