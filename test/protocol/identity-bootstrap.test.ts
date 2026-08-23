// End-to-end: createNewIdentity against a real did:webvh anchor (fakeAnchor),
// a real core (SqliteMlsDeliveryService + SqliteTrustedDeviceRoster behind
// createBisetCoreFetchHandler), and REAL DID resolution
// (WebvhSigningKeyResolver) for both the MLS DS's and the roster's signature
// verification -- confirms the whole identity-creation flow (genesis ->
// device verificationMethod -> self-group -> roster -> KeyPackage pool)
// actually interoperates, not just against hand-built fixtures.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { Database } from 'bun:sqlite'
import { createBisetCoreFetchHandler } from '../../src/core/app.ts'
import { SqliteMlsDeliveryService } from '../../src/core/mediation/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/core/mediation/mls-delivery-authorizer.ts'
import { SqliteTrustedDeviceRoster } from '../../src/core/identity/sqlite-device-roster.ts'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'
import { WebvhSigningKeyResolver } from '../../src/core/identity/webvh-signing-key-resolver.ts'
import { createNewIdentity } from '../../src/identity/bootstrap.ts'
import { resolve } from '../../src/identity/webvh/resolver.ts'
import { didWebToHttpsUrl, buildWebDid } from '../../src/identity/web/identifier.ts'
import { memberKids, setMlsAuthService } from '../../src/mls/group.ts'
import { defaultAuthenticationService } from '../../src/mls/vendor/index.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { MlsKeyPackageStore } from '../../src/mls/keypackage-store.ts'
import type { IdentityRecord, IdentityRecordStore } from '../../src/identity/record-store.ts'
import type { OwnKeyPackage } from '../../src/mls/group.ts'

const dsPath = `/tmp/biset-identity-bootstrap-ds-${process.pid}-${Date.now()}.sqlite`
const rosterPath = `/tmp/biset-identity-bootstrap-roster-${process.pid}-${Date.now()}.sqlite`
const CORE_ORIGIN = 'https://core.test.example'

afterEach(() => {
  for (const base of [dsPath, rosterPath]) {
    for (const suffix of ['', '-wal', '-shm']) {
      try { rmSync(`${base}${suffix}`) } catch {}
    }
  }
  // createNewIdentity installs webvhAuthenticationService as MLS's ONE global
  // AuthenticationService (group.ts's own note on why there is only one) --
  // every other test in this process expects the accept-all default, so this
  // must not leak past this file's own tests.
  setMlsAuthService(defaultAuthenticationService)
})

function memoryIdentityRecordStore(): IdentityRecordStore {
  const rows = new Map<string, IdentityRecord>()
  return {
    async get(did) { return rows.get(did) },
    async put(record) { rows.set(record.did, record) },
    async list() { return [...rows.values()] },
  }
}

function memorySelfGroupStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

function memoryKeyPackageStore(): MlsKeyPackageStore & { size(): number } {
  const byRef = new Map<string, OwnKeyPackage>()
  return {
    async mint(kid, count) {
      const { generateOwnKeyPackage, keyPackageRefOf } = await import('../../src/mls/group.ts')
      const minted: OwnKeyPackage[] = []
      for (let i = 0; i < count; i++) {
        const own = await generateOwnKeyPackage(kid)
        byRef.set(await keyPackageRefOf(own.publicPackage), own)
        minted.push(own)
      }
      return minted
    },
    async takeForWelcome() { throw new Error('not used by this test') },
    size() { return byRef.size },
  }
}

/** Routes by origin to the anchor (any host) or to core (CORE_ORIGIN) --
 * real DID resolution (WebvhSigningKeyResolver) needs globalThis.fetch
 * itself to reach both, since it takes no fetch parameter of its own. */
function combinedFetch(anchorFetch: typeof fetch, coreHandle: (request: Request) => Promise<Response>): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init)
    if (request.url.startsWith(CORE_ORIGIN)) return coreHandle(request)
    return anchorFetch(input, init)
  }) as typeof fetch
}

describe('createNewIdentity', () => {
  test('genesis, device verificationMethod, self-group, roster, and KeyPackage pool all land', async () => {
    const anchor = fakeAnchor()
    const ds = SqliteMlsDeliveryService.open(dsPath)
    const roster = SqliteTrustedDeviceRoster.open(rosterPath)
    const keyResolver = new WebvhSigningKeyResolver()
    const resolveEd25519PublicKey = (kid: string) => keyResolver.resolveEd25519PublicKey(kid)
    const dsVerifier = new Ed25519MlsDsSignatureVerifier({ resolveEd25519PublicKey })
    const rosterVerifier = new Ed25519DeviceControlSignatureVerifier({ resolveEd25519PublicKey })
    const coreHandle = createBisetCoreFetchHandler({
      roster: { store: roster, verifier: rosterVerifier },
      mlsDelivery: { store: ds, verifier: dsVerifier, isLiveDevice: async () => true },
    })

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const recordStore = memoryIdentityRecordStore()
      const selfGroupStore = memorySelfGroupStore()
      const keyStore = memoryKeyPackageStore()

      const created = await createNewIdentity(recordStore, selfGroupStore, keyStore, {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, didWebMirror: true,
      })

      expect(created.record.did).toContain('did:webvh:')
      expect(created.record.deviceKid).toContain(created.record.did)
      expect(memberKids(created.selfGroupState, created.record.did)).toEqual([created.record.deviceKid])

      // did:webvh actually resolves, with this device's key present.
      const doc = await resolve(created.record.did)
      expect(doc?.verificationMethod.some(vm => vm.id === created.record.deviceKid)).toBe(true)

      // did:web mirror was published at the same subdomain.
      const mirrorResponse = await anchor.fetch(didWebToHttpsUrl(buildWebDid('y.test.example')))
      expect(mirrorResponse.status).toBe(200)

      // The roster trusts this device as of genesis.
      expect(await roster.isTrustedDevice(created.record.did, created.record.deviceKid!)).toBe(true)
      expect(await roster.deliveryFloor(created.record.did, created.record.deviceKid!)).toBe('0')

      // Persisted locally, and the KeyPackage pool was topped up at the DS.
      expect(await recordStore.get(created.record.did)).toEqual(created.record)
      expect(keyStore.size()).toBeGreaterThan(0)

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
