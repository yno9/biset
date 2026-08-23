// End-to-end across the pieces added for PLAN.md §4.1: a real MLS self group
// (src/mls/group.ts, the vendored ts-mls) produces an accepted commit, the
// producer (src/mls/roster-projection.ts) turns it into a signed
// RosterInstallV1, and core's installRosterProjection accepts it into the
// roster — using the same Ed25519DeviceControlSignatureVerifier the rest of
// core's device-control checks use.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createMlsGroup, epochOf, generateOwnKeyPackage, rekey } from '../../src/mls/group.ts'
import { buildAcceptedSelfGroupProjection, signRosterInstall } from '../../src/mls/roster-projection.ts'
import { installRosterProjection } from '../../src/core/identity/authorizers.ts'
import { MemoryTrustedDeviceRoster, type AcceptedSelfGroupProjectionV1 } from '../../src/core/identity/device-roster.ts'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'

const did = 'did:web:alice.example'
const kid = `${did}#device-a`
const signingKeyId = `${did}#device-a-sign`

describe('MLS accepted commit -> RosterInstallV1 -> core roster', () => {
  test('a genesis self group installs its sole device as the roster', async () => {
    const own = await generateOwnKeyPackage(kid)
    const state = await createMlsGroup(crypto.getRandomValues(new Uint8Array(32)), own)

    const deviceSigningPrivateKey = ed25519.utils.randomSecretKey()
    const deviceSigningPublicKey = ed25519.getPublicKey(deviceSigningPrivateKey)

    const projection = await buildAcceptedSelfGroupProjection(did, 'self-group-alice', did, state, undefined, {
      signingKeyIdForKid: () => signingKeyId,
      deliveryFloorForNewDevice: async () => '0',
    })
    expect(projection.devices).toEqual([{ deviceId: kid, deliveryFloor: '0', signingKeyId }])
    expect(projection.epoch).toBe(String(epochOf(state)))

    const install = await signRosterInstall(projection, kid, bytes => ed25519.sign(bytes, deviceSigningPrivateKey))

    const roster = new MemoryTrustedDeviceRoster()
    const verifier = new Ed25519DeviceControlSignatureVerifier({
      async resolveEd25519PublicKey(keyId) { return keyId === signingKeyId ? deviceSigningPublicKey : undefined },
    })
    expect(await installRosterProjection(roster, verifier, install)).toBe('installed')
    expect(await roster.isTrustedDevice(did, kid)).toBe(true)
    expect(await roster.deliveryFloor(did, kid)).toBe('0')
  })

  test('a later epoch keeps an existing device\'s deliveryFloor and advances the epoch', async () => {
    const own = await generateOwnKeyPackage(kid)
    const genesisState = await createMlsGroup(crypto.getRandomValues(new Uint8Array(32)), own)
    const previous: AcceptedSelfGroupProjectionV1 = await buildAcceptedSelfGroupProjection(did, 'self-group-alice', did, genesisState, undefined, {
      signingKeyIdForKid: () => signingKeyId,
      deliveryFloorForNewDevice: async () => '7',
    })

    const { state: rekeyedState } = await rekey(genesisState)
    const next = await buildAcceptedSelfGroupProjection(did, 'self-group-alice', did, rekeyedState, previous, {
      signingKeyIdForKid: () => signingKeyId,
      deliveryFloorForNewDevice: async () => { throw new Error('should not allocate a floor for an already-known device') },
    })

    expect(next.devices).toEqual([{ deviceId: kid, deliveryFloor: '7', signingKeyId }])
    expect(BigInt(next.epoch)).toBeGreaterThan(BigInt(previous.epoch))
  })
})
