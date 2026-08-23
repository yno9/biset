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
import { SqliteMlsDeliveryService } from '../../src/core/mediation/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/core/mediation/mls-delivery-authorizer.ts'
import { createMlsDeliveryHttpHandler } from '../../src/core/mediation/mls-delivery-http.ts'
import { SqliteTrustedDeviceRoster } from '../../src/core/identity/sqlite-device-roster.ts'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'
import { createRosterInstallHttpHandler } from '../../src/core/identity/roster-http.ts'
import { CoreMlsDeliveryTransport } from '../../src/mls/core-mls-delivery-transport.ts'
import { CoreRosterInstallTransport } from '../../src/mls/core-roster-install-transport.ts'
import { epochOf, generateOwnKeyPackage, memberKids, processIncoming } from '../../src/mls/group.ts'
import { ensureSelfGroupWithRosterInstall, installCurrentRosterProjection, selfGroupIdHex } from '../../src/mls/self-group.ts'
import { mlsDeliveriesPullSigningBytes } from '../../src/protocol/signing.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { OwnKeyPackage } from '../../src/mls/group.ts'
import type { ClientState } from '../../src/mls/vendor/index.ts'

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
  const mlsTransport = new CoreMlsDeliveryTransport({ baseUrl: 'https://core.example', fetch: (input, init) => dsHandle(new Request(input, init)) })

  const roster = SqliteTrustedDeviceRoster.open(rosterPath)
  const rosterVerifier = new Ed25519DeviceControlSignatureVerifier({ resolveEd25519PublicKey })
  const rosterHandle = createRosterInstallHttpHandler(roster, rosterVerifier)
  const rosterTransport = new CoreRosterInstallTransport({ baseUrl: 'https://core.example', fetch: (input, init) => rosterHandle(new Request(input, init)) })

  return { ds, roster, mlsTransport, rosterTransport }
}

/** Pulls every delivery this device hasn't seen yet and applies it in order
 * -- the minimal stand-in for the catch-up flow self-group.ts's header
 * deliberately leaves out, just enough for this test to give device A a
 * genuine post-join view of the group instead of hand-waving it. */
async function pullAndApply(
  transport: CoreMlsDeliveryTransport,
  state: ClientState,
  identityId: string,
  deviceKid: string,
  sign: (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>,
): Promise<ClientState> {
  const pull = { version: 1 as const, groupId: selfGroupIdHex(identityId), identityId, requesterKid: deviceKid, afterSeq: 0, requestedAt: new Date().toISOString() }
  const entries = await transport.pullDeliveries({ ...pull, signature: await sign(mlsDeliveriesPullSigningBytes(pull)) })
  let next = state
  for (const entry of entries) {
    // Only a commit made FROM this device's current epoch is one it hasn't
    // already applied -- the log also holds this very device's own earlier
    // commits (e.g. its genesis publishGroupInfo), which re-decrypting would
    // fail against an already-advanced key schedule.
    if (entry.kind !== 'commit' || entry.epoch !== epochOf(next).toString()) continue
    const result = await processIncoming(next, entry.payload)
    next = result.state
  }
  return next
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

    const stateA = await ensureSelfGroupWithRosterInstall(
      memoryStore(), mlsTransport, rosterTransport, identityId, deviceAKid, kpA, signerFor(kpA),
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

    // Device A only knows the new epoch once it actually processes device
    // B's external commit -- pulled from the DS the same way a real second
    // session would, then applied with processIncoming. Only then does its
    // own view of the group (and so its own roster projection) include B.
    const stateAAfterB = await pullAndApply(mlsTransport, stateA!, identityId, deviceAKid, signerFor(kpA))
    expect(new Set(memberKids(stateAAfterB, identityId))).toEqual(new Set([deviceAKid, deviceBKid]))

    // Device A, an existing trusted device, reflects the new epoch on B's behalf.
    const outcome = await installCurrentRosterProjection(
      rosterTransport, identityId, deviceAKid, stateAAfterB, signerFor(kpA), async () => '99',
    )
    expect(outcome).toBe('installed')
    expect(await roster.isTrustedDevice(identityId, deviceBKid)).toBe(true)
    expect(await roster.deliveryFloor(identityId, deviceBKid)).toBe('99')
    // Device A's own floor from genesis is untouched by device B's join.
    expect(await roster.deliveryFloor(identityId, deviceAKid)).toBe('0')

    ds.close()
    roster.close()
  })
})
