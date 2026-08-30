import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  createMlsDeviceCredential,
  decodeMlsDeviceCredential,
  encodeMlsDeviceCredential,
  mlsDeviceKid,
  verifyMlsDeviceCredential,
} from '../../src/mls/device-credential.ts'

describe('Root-signed MLS device credential', () => {
  test('binds one deterministic device kid to its MLS leaf key without a DID verificationMethod', () => {
    const root = ed25519.utils.randomSecretKey()
    const leaf = ed25519.utils.randomSecretKey()
    const leafPublic = ed25519.getPublicKey(leaf)
    const did = 'did:webvh:QmRoot:alice.example'
    const credential = createMlsDeviceCredential(did, '1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', leafPublic, root, root)
    expect(credential.deviceKid).toBe(mlsDeviceKid(did, leafPublic))
    const decoded = decodeMlsDeviceCredential(encodeMlsDeviceCredential(credential))
    expect(verifyMlsDeviceCredential(decoded, ed25519.getPublicKey(root), leafPublic)).toBeTrue()
  })

  test('rejects another leaf key, root, or non-canonical encoding', () => {
    const root = ed25519.utils.randomSecretKey()
    const leafPublic = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const credential = createMlsDeviceCredential('did:webvh:QmRoot:alice.example', '1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', leafPublic, root, root)
    expect(verifyMlsDeviceCredential(credential, ed25519.getPublicKey(root), ed25519.getPublicKey(ed25519.utils.randomSecretKey()))).toBeFalse()
    expect(verifyMlsDeviceCredential(credential, ed25519.getPublicKey(ed25519.utils.randomSecretKey()))).toBeFalse()
    const parsed = JSON.parse(new TextDecoder().decode(encodeMlsDeviceCredential(credential)))
    const reordered = JSON.stringify({ version: parsed.version, identityId: parsed.identityId, generation: parsed.generation, deviceKid: parsed.deviceKid, signaturePublicKey: parsed.signaturePublicKey, rootSignature: parsed.rootSignature, signSignature: parsed.signSignature })
    expect(() => decodeMlsDeviceCredential(new TextEncoder().encode(reordered))).toThrow('not canonical')
  })
})
