import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'
import { ingressPullSigningBytes, restoreControlPullSigningBytes, vaultDeliveryPullSigningBytes } from '../../src/protocol/signing.ts'

const privateKey = ed25519.utils.randomSecretKey()
const publicKey = ed25519.getPublicKey(privateKey)
const device = { deviceId: 'device-a', deliveryFloor: '1', signingKeyId: 'did:web:alice.example#device-a' }

describe('Ed25519 device control verifier', () => {
  test('resolves only the roster-selected public key ID and verifies the canonical pull bytes', async () => {
    const verifier = new Ed25519DeviceControlSignatureVerifier({
      async resolveEd25519PublicKey(keyId) { return keyId === device.signingKeyId ? publicKey : undefined },
    })
    const unsigned = { version: 1 as const, identityId: 'did:web:alice.example', recipientDeviceId: 'device-a', after: '7', requestedAt: '2026-08-21T00:00:00.000Z' }
    const pull = { ...unsigned, signature: ed25519.sign(vaultDeliveryPullSigningBytes(unsigned), privateKey) }
    expect(await verifier.verifyVaultDeliveryPull(pull, device)).toBe(true)
    expect(await verifier.verifyVaultDeliveryPull({ ...pull, after: '8' }, device)).toBe(false)
  })

  test('does not accept a valid signature under a different roster key ID', async () => {
    const verifier = new Ed25519DeviceControlSignatureVerifier({ async resolveEd25519PublicKey() { return undefined } })
    const unsigned = { version: 1 as const, identityId: 'did:web:alice.example', recipientDeviceId: 'device-a', after: '7', requestedAt: '2026-08-21T00:00:00.000Z' }
    const pull = { ...unsigned, signature: ed25519.sign(vaultDeliveryPullSigningBytes(unsigned), privateKey) }
    expect(await verifier.verifyVaultDeliveryPull(pull, device)).toBe(false)
  })

  test('verifies ingress retrieval as a distinct signed device control', async () => {
    const verifier = new Ed25519DeviceControlSignatureVerifier({
      async resolveEd25519PublicKey(keyId) { return keyId === device.signingKeyId ? publicKey : undefined },
    })
    const unsigned = { version: 1 as const, identityId: 'did:web:alice.example', recipientDeviceId: 'device-a', requestedAt: '2026-08-21T00:00:00.000Z' }
    const pull = { ...unsigned, signature: ed25519.sign(ingressPullSigningBytes(unsigned), privateKey) }
    expect(await verifier.verifyIngressPull(pull, device)).toBe(true)
    expect(await verifier.verifyIngressPull({ ...pull, recipientDeviceId: 'device-b' }, device)).toBe(false)
  })

  test('verifies a restore poll as a distinct signed device control', async () => {
    const verifier = new Ed25519DeviceControlSignatureVerifier({
      async resolveEd25519PublicKey(keyId) { return keyId === device.signingKeyId ? publicKey : undefined },
    })
    const unsigned = { version: 1 as const, identityId: 'did:web:alice.example', deviceId: 'device-a', kind: 'requests' as const, requestedAt: '2026-08-21T00:00:00.000Z' }
    const pull = { ...unsigned, signature: ed25519.sign(restoreControlPullSigningBytes(unsigned), privateKey) }
    expect(await verifier.verifyRestoreControlPull(pull, device)).toBe(true)
    expect(await verifier.verifyRestoreControlPull({ ...pull, kind: 'offers' }, device)).toBe(false)
  })
})
