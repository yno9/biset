import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { MemoryTrustedDeviceRoster, type AcceptedSelfGroupProjectionV1 } from '../../src/core/identity/device-roster.ts'
import { installRosterProjection } from '../../src/core/identity/authorizers.ts'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'
import { rosterInstallSigningBytes, type RosterInstallV1 } from '../../src/core/identity/roster-install.ts'

const deviceAKey = ed25519.utils.randomSecretKey()
const deviceAPublicKey = ed25519.getPublicKey(deviceAKey)
const deviceBKey = ed25519.utils.randomSecretKey()
const deviceBPublicKey = ed25519.getPublicKey(deviceBKey)
const strangerKey = ed25519.utils.randomSecretKey()

function verifier() {
  return new Ed25519DeviceControlSignatureVerifier({
    async resolveEd25519PublicKey(_keyId, _identityId, credential) { return credential[0] === 1 ? deviceAPublicKey : credential[0] === 2 ? deviceBPublicKey : undefined },
  })
}

function projection(overrides: Partial<AcceptedSelfGroupProjectionV1> = {}): AcceptedSelfGroupProjectionV1 {
  return {
    version: 1,
    identityId: 'did:web:alice.example',
    selfGroupId: 'self-group-alice',
    epoch: '1',
    devices: [{ deviceId: 'device-a', deliveryFloor: '0', signingPublicKey: deviceAPublicKey, deviceCredential: new Uint8Array([1]) }],
    acceptedAt: '2026-08-23T00:00:00.000Z',
    ...overrides,
  }
}

function signedInstall(unsigned: Omit<RosterInstallV1, 'signature'>, signerKey: Uint8Array): RosterInstallV1 {
  return { ...unsigned, signature: ed25519.sign(rosterInstallSigningBytes(unsigned), signerKey) }
}

describe('installRosterProjection (core as MLS DS)', () => {
  test('genesis: a new identity accepts self-attestation from a device in its own projection', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    const install = signedInstall({ version: 1, projection: projection(), installerDeviceId: 'device-a', installedAt: '2026-08-23T00:00:00.000Z' }, deviceAKey)
    expect(await installRosterProjection(roster, verifier(), install)).toBe('installed')
    expect(await roster.isTrustedDevice('did:web:alice.example', 'device-a')).toBe(true)
  })

  test('genesis: rejects self-attestation from a device not even in the offered projection', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    const install = signedInstall({ version: 1, projection: projection(), installerDeviceId: 'device-b', installedAt: '2026-08-23T00:00:00.000Z' }, deviceBKey)
    expect(await installRosterProjection(roster, verifier(), install)).toBe('rejected')
    expect(await roster.projection('did:web:alice.example')).toBeUndefined()
  })

  test('post-genesis: only a device the roster already trusts may install the next epoch', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    await installRosterProjection(roster, verifier(), signedInstall(
      { version: 1, projection: projection(), installerDeviceId: 'device-a', installedAt: '2026-08-23T00:00:00.000Z' },
      deviceAKey,
    ))

    const next = projection({
      epoch: '2',
      devices: [
        { deviceId: 'device-a', deliveryFloor: '0', signingPublicKey: deviceAPublicKey, deviceCredential: new Uint8Array([1]) },
        { deviceId: 'device-b', deliveryFloor: '5', signingPublicKey: deviceBPublicKey, deviceCredential: new Uint8Array([2]) },
      ],
      acceptedAt: '2026-08-23T00:01:00.000Z',
    })
    const install = signedInstall({ version: 1, projection: next, installerDeviceId: 'device-a', installedAt: '2026-08-23T00:01:00.000Z' }, deviceAKey)
    expect(await installRosterProjection(roster, verifier(), install)).toBe('installed')
    expect(await roster.isTrustedDevice('did:web:alice.example', 'device-b')).toBe(true)
  })

  test('post-genesis: a device the CURRENT roster does not trust cannot install a new epoch, even if it signs its own way in', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    await installRosterProjection(roster, verifier(), signedInstall(
      { version: 1, projection: projection(), installerDeviceId: 'device-a', installedAt: '2026-08-23T00:00:00.000Z' },
      deviceAKey,
    ))

    // device-b is not yet a trusted device; it cannot bootstrap itself in by
    // signing an install that adds itself.
    const forged = projection({
      epoch: '2',
      devices: [{ deviceId: 'device-b', deliveryFloor: '0', signingPublicKey: deviceBPublicKey, deviceCredential: new Uint8Array([2]) }],
      acceptedAt: '2026-08-23T00:01:00.000Z',
    })
    const install = signedInstall({ version: 1, projection: forged, installerDeviceId: 'device-b', installedAt: '2026-08-23T00:01:00.000Z' }, deviceBKey)
    expect(await installRosterProjection(roster, verifier(), install)).toBe('rejected')
    expect(await roster.isTrustedDevice('did:web:alice.example', 'device-a')).toBe(true)
    expect(await roster.isTrustedDevice('did:web:alice.example', 'device-b')).toBe(false)
  })

  test('rejects a well-formed install whose signature does not match the claimed installer', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    const install = signedInstall({ version: 1, projection: projection(), installerDeviceId: 'device-a', installedAt: '2026-08-23T00:00:00.000Z' }, strangerKey)
    expect(await installRosterProjection(roster, verifier(), install)).toBe('rejected')
  })

  test('tie-break: a conflicting install for the same epoch is rejected once one has landed', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    await installRosterProjection(roster, verifier(), signedInstall(
      { version: 1, projection: projection(), installerDeviceId: 'device-a', installedAt: '2026-08-23T00:00:00.000Z' },
      deviceAKey,
    ))

    const conflicting = projection({ devices: [{ deviceId: 'device-a', deliveryFloor: '9', signingPublicKey: deviceAPublicKey, deviceCredential: new Uint8Array([1]) }] })
    const install = signedInstall({ version: 1, projection: conflicting, installerDeviceId: 'device-a', installedAt: '2026-08-23T00:00:01.000Z' }, deviceAKey)
    await expect(installRosterProjection(roster, verifier(), install)).rejects.toThrow('conflicting device roster')
  })
})
