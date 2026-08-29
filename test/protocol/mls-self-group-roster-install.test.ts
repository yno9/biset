// End-to-end: ensureSelfGroupWithRosterInstall / installCurrentRosterProjection
// against real MLS state, a real DS (SqliteMlsDeliveryService), and a real
// roster (SqliteTrustedDeviceRoster) behind their real HTTP handlers.
//
// Confirms the genesis-vs-post-genesis installer rule from authorizers.ts's
// installRosterProjection actually plays out end to end: device A's genesis
// join installs itself, but device B's own external-join install attempt is
// rejected (it is not yet in the previous epoch's roster) until device A
// reflects the new epoch on its behalf.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { Database } from 'bun:sqlite'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteMlsDeliveryService } from '../../src/coordinator/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/coordinator/mls-delivery-authorizer.ts'
import { createMlsDeliveryHttpHandler } from '../../src/coordinator/mls-delivery-http.ts'
import { SqliteTrustedDeviceRoster } from '../../src/core/identity/sqlite-device-roster.ts'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'
import { createRosterInstallHttpHandler } from '../../src/core/identity/roster-http.ts'
import { CoordinatorMlsDeliveryTransport } from '../../src/mls/coordinator-mls-delivery-transport.ts'
import { CoreRosterInstallTransport } from '../../src/mls/core-roster-install-transport.ts'
import { generateOwnKeyPackage, memberKids } from '../../src/mls/group.ts'
import { ensureSelfGroupWithRosterInstall, reflectPendingSelfGroupCommits } from '../../src/mls/self-group.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { OwnKeyPackage } from '../../src/mls/group.ts'

const dsPath = `/tmp/biset-self-group-roster-ds-${process.pid}-${Date.now()}.sqlite`
const rosterPath = `/tmp/biset-self-group-roster-db-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const deviceAKid = `${identityId}#device-a`
const deviceBKid = `${identityId}#device-b`

afterEach(() => {
  for (const base of [dsPath, rosterPath]) {
    for (const suffix of ['', '-wal', '-shm']) {
      try { rmSync(`${base}${suffix}`) } catch {}
    }
  }
})

function memoryStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

function signerFor(kp: OwnKeyPackage) {
  return (bytes: Uint8Array) => ed25519.sign(bytes, kp.privatePackage.signaturePrivateKey)
}

/** Both the DS and the roster resolve each device's ACTUAL MLS leaf
 * signature key, same as mls-self-group-bootstrap.test.ts. */
function setup(kids: Record<string, OwnKeyPackage>) {
  const resolveEd25519PublicKey = async (kid: string) => kids[kid]?.publicPackage.leafNode.signaturePublicKey

  const ds = SqliteMlsDeliveryService.open(dsPath)
  const dsVerifier = new Ed25519MlsDsSignatureVerifier({ resolveEd25519PublicKey })
  const dsHandle = createMlsDeliveryHttpHandler(ds, dsVerifier, async () => true)
  const mlsTransport = new CoordinatorMlsDeliveryTransport({ baseUrl: 'https://core.example', fetch: (input, init) => dsHandle(new Request(input, init)) })

  const roster = SqliteTrustedDeviceRoster.open(rosterPath)
  const rosterVerifier = new Ed25519DeviceControlSignatureVerifier({ resolveEd25519PublicKey })
  const rosterHandle = createRosterInstallHttpHandler(roster, rosterVerifier)
  const rosterTransport = new CoreRosterInstallTransport({ baseUrl: 'https://core.example', fetch: (input, init) => rosterHandle(new Request(input, init)) })

  return { ds, roster, mlsTransport, rosterTransport }
}

describe('roster install atop self-group bootstrap', () => {
  test('genesis device installs its own single-device roster', async () => {
    const kpA = await generateOwnKeyPackage(deviceAKid)
    const { ds, roster, mlsTransport, rosterTransport } = setup({ [deviceAKid]: kpA })

    const stateA = await ensureSelfGroupWithRosterInstall(
      memoryStore(), mlsTransport, rosterTransport, identityId, deviceAKid, kpA, signerFor(kpA),
      async () => '0',
    )
    expect(stateA).toBeDefined()
    expect(await roster.isTrustedDevice(identityId, deviceAKid)).toBe(true)
    expect(await roster.deliveryFloor(identityId, deviceAKid)).toBe('0')

    ds.close()
    roster.close()
  })

  test('a newly-joined device cannot install itself; the existing device reflects it instead', async () => {
    const kpA = await generateOwnKeyPackage(deviceAKid)
    const kpB = await generateOwnKeyPackage(deviceBKid)
    const { ds, roster, mlsTransport, rosterTransport } = setup({ [deviceAKid]: kpA, [deviceBKid]: kpB })
    const storeA = memoryStore()

    const stateA = await ensureSelfGroupWithRosterInstall(
      storeA, mlsTransport, rosterTransport, identityId, deviceAKid, kpA, signerFor(kpA),
      async () => '0',
    )
    expect(stateA).toBeDefined()

    const stateB = await ensureSelfGroupWithRosterInstall(
      memoryStore(), mlsTransport, rosterTransport, identityId, deviceBKid, kpB, signerFor(kpB),
      async () => '99',
    )
    expect(stateB).toBeDefined()
    expect(new Set(memberKids(stateB!, identityId))).toEqual(new Set([deviceAKid, deviceBKid]))

    // Device B's own install attempt was rejected: it is not yet a trusted
    // device under the previous (device-A-only) epoch.
    expect(await roster.isTrustedDevice(identityId, deviceBKid)).toBe(false)
    expect(await roster.isTrustedDevice(identityId, deviceAKid)).toBe(true)

    // Device A only knows the new epoch once it actually catches up on
    // device B's external commit -- reflectPendingSelfGroupCommits pulls it
    // from the DS the same way a real second session would, applies it, and
    // (since the epoch advanced) reflects the new roster on B's behalf.
    const stateAAfterB = await reflectPendingSelfGroupCommits(
      storeA, mlsTransport, rosterTransport, identityId, deviceAKid, signerFor(kpA), async () => '99',
    )
    expect(new Set(memberKids(stateAAfterB!, identityId))).toEqual(new Set([deviceAKid, deviceBKid]))
    expect(await roster.isTrustedDevice(identityId, deviceBKid)).toBe(true)
    expect(await roster.deliveryFloor(identityId, deviceBKid)).toBe('99')
    // Device A's own floor from genesis is untouched by device B's join.
    expect(await roster.deliveryFloor(identityId, deviceAKid)).toBe('0')

    ds.close()
    roster.close()
  })

  test('reflectPendingSelfGroupCommits is a no-op when there is nothing new', async () => {
    const kpA = await generateOwnKeyPackage(deviceAKid)
    const { ds, roster, mlsTransport, rosterTransport } = setup({ [deviceAKid]: kpA })
    const storeA = memoryStore()

    const stateA = await ensureSelfGroupWithRosterInstall(
      storeA, mlsTransport, rosterTransport, identityId, deviceAKid, kpA, signerFor(kpA),
      async () => '0',
    )
    expect(stateA).toBeDefined()

    const brokenRosterTransport = new CoreRosterInstallTransport({ baseUrl: 'https://core.example', fetch: async () => { throw new Error('roster must not be touched when the epoch did not advance') } })
    const result = await reflectPendingSelfGroupCommits(
      storeA, mlsTransport, brokenRosterTransport, identityId, deviceAKid, signerFor(kpA), async () => '99',
    )
    expect(result).toBe(stateA!)

    ds.close()
    roster.close()
  })

  test('reflectPendingSelfGroupCommits returns undefined when this device has no stored self-group state', async () => {
    const kpA = await generateOwnKeyPackage(deviceAKid)
    const { ds, roster, mlsTransport, rosterTransport } = setup({ [deviceAKid]: kpA })

    const result = await reflectPendingSelfGroupCommits(
      memoryStore(), mlsTransport, rosterTransport, identityId, deviceAKid, signerFor(kpA), async () => '0',
    )
    expect(result).toBeUndefined()

    ds.close()
    roster.close()
  })
})
