import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createRosterInstallHttpHandler } from '../../src/core/identity/roster-http.ts'
import { MemoryTrustedDeviceRoster, type AcceptedSelfGroupProjectionV1 } from '../../src/core/identity/device-roster.ts'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'
import { encodeRosterInstallWire, rosterInstallSigningBytes, type RosterInstallV1 } from '../../src/core/identity/roster-install.ts'

const deviceAKey = ed25519.utils.randomSecretKey()
const deviceAPublicKey = ed25519.getPublicKey(deviceAKey)

function projection(): AcceptedSelfGroupProjectionV1 {
  return {
    version: 1,
    identityId: 'did:web:alice.example',
    selfGroupId: 'self-group-alice',
    epoch: '1',
    devices: [{ deviceId: 'device-a', deliveryFloor: '0', signingPublicKey: deviceAPublicKey, deviceCredential: new Uint8Array([1]) }],
    acceptedAt: '2026-08-23T00:00:00.000Z',
  }
}

function signedInstall(signerKey: Uint8Array): RosterInstallV1 {
  const unsigned = { version: 1 as const, projection: projection(), installerDeviceId: 'device-a', installedAt: '2026-08-23T00:00:00.000Z' }
  return { ...unsigned, signature: ed25519.sign(rosterInstallSigningBytes(unsigned), signerKey) }
}

function handler() {
  const roster = new MemoryTrustedDeviceRoster()
  const verifier = new Ed25519DeviceControlSignatureVerifier({
    async resolveEd25519PublicKey(keyId, _identityId, credential) { return keyId === 'device-a' && credential[0] === 1 ? deviceAPublicKey : undefined },
  })
  return { roster, handle: createRosterInstallHttpHandler(roster, verifier) }
}

describe('roster install HTTP endpoint', () => {
  test('installs a validly signed genesis projection', async () => {
    const { roster, handle } = handler()
    const request = new Request('https://core.example/v1/roster/install', { method: 'POST', body: encodeRosterInstallWire(signedInstall(deviceAKey)) })
    const response = await handle(request)
    expect(response.status).toBe(201)
    expect(await roster.isTrustedDevice('did:web:alice.example', 'device-a')).toBe(true)
  })

  test('rejects an install signed by the wrong key', async () => {
    const { roster, handle } = handler()
    const strangerKey = ed25519.utils.randomSecretKey()
    const request = new Request('https://core.example/v1/roster/install', { method: 'POST', body: encodeRosterInstallWire(signedInstall(strangerKey)) })
    const response = await handle(request)
    expect(response.status).toBe(403)
    expect(await roster.projection('did:web:alice.example')).toBeUndefined()
  })

  test('rejects malformed JSON with 400', async () => {
    const { handle } = handler()
    const response = await handle(new Request('https://core.example/v1/roster/install', { method: 'POST', body: 'not json' }))
    expect(response.status).toBe(400)
  })

  test('rejects an unknown path with 404', async () => {
    const { handle } = handler()
    const response = await handle(new Request('https://core.example/v1/roster/status', { method: 'POST', body: '{}' }))
    expect(response.status).toBe(404)
  })

  test('rejects a non-POST method with 405', async () => {
    const { handle } = handler()
    const response = await handle(new Request('https://core.example/v1/roster/install', { method: 'GET' }))
    expect(response.status).toBe(405)
  })
})
