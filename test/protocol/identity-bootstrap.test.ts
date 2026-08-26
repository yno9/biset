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
import { ed25519 } from '@noble/curves/ed25519.js'
import { createBisetCoreFetchHandler } from '../../src/core/app.ts'
import { SqliteMlsDeliveryService } from '../../src/core/mediation/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/core/mediation/mls-delivery-authorizer.ts'
import { MemoryVaultDeliveryStore } from '../../src/core/mediation/vault-delivery-store.ts'
import { SqliteTrustedDeviceRoster } from '../../src/core/identity/sqlite-device-roster.ts'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'
import { rosterBackedVaultDeliveryAuthorizer } from '../../src/core/identity/authorizers.ts'
import { WebvhSigningKeyResolver } from '../../src/core/identity/webvh-signing-key-resolver.ts'
import { buildVaultCryptoBoundary, createNewIdentity, enableDidComm, maintainSelfGroup, restoreIdentity } from '../../src/identity/bootstrap.ts'
import { fetchRouting } from '../../src/didcomm/webvh-routing.ts'
import { DidCommCredentialReader } from '../../src/vault/didcomm-credential-reader.ts'
import { DidCommCredentialVaultSink } from '../../src/vault/didcomm-credential-sink.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { seedToMnemonic } from '../../src/identity/seed.ts'
import { resolve } from '../../src/identity/webvh/resolver.ts'
import { didWebToHttpsUrl, buildWebDid } from '../../src/identity/web/identifier.ts'
import { epochOf, memberKids, setMlsAuthService } from '../../src/mls/group.ts'
import { defaultAuthenticationService } from '../../src/mls/vendor/index.ts'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import { mlsEpoch } from '../../src/protocol/ids.ts'
import { vaultDeliveryAppendSigningBytes } from '../../src/protocol/signing.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { MlsKeyPackageStore } from '../../src/mls/keypackage-store.ts'
import type { IdentityRecord, IdentityRecordStore } from '../../src/identity/record-store.ts'
import type { OwnKeyPackage } from '../../src/mls/group.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { SegmentKeyWrapV1 } from '../../src/protocol/vault.ts'

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

function memoryWrapStore(): SegmentKeyWrapReader & SegmentKeyWrapWriter {
  const rows = new Map<string, SegmentKeyWrapV1>()
  const key = (identityId: string, segmentId: string, epoch: string) => `${identityId} ${segmentId} ${epoch}`
  return {
    async readSegmentKeyWrap(id, segmentId, epoch) { return rows.get(key(id, segmentId, epoch)) },
    async writeSegmentKeyWrap(wrap) { rows.set(key(wrap.identityId, wrap.segmentId, wrap.recipientEpoch), wrap) },
  }
}

function memorySegmentStore(): ActiveVaultSegmentStore {
  const rows: VaultSegmentRecord[] = []
  return {
    async currentSegment(identityId) { return rows.find(r => r.identityId === identityId && !r.sealed) },
    async allSegments(identityId) { return rows.filter(r => r.identityId === identityId) },
    async sealAndActivateSegment(next) {
      for (const row of rows) if (row.identityId === next.identityId && !row.sealed) row.sealed = true
      rows.push({ ...next })
    },
    async recordSegmentRewrapped(identityId, segmentId, epoch) {
      const row = rows.find(r => r.identityId === identityId && r.segmentId === segmentId)
      if (!row) throw new Error('recordSegmentRewrapped: no such segment')
      row.epoch = epoch
    },
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

function setupCore() {
  const anchor = fakeAnchor()
  const ds = SqliteMlsDeliveryService.open(dsPath)
  const roster = SqliteTrustedDeviceRoster.open(rosterPath)
  const keyResolver = new WebvhSigningKeyResolver()
  const resolveEd25519PublicKey = (kid: string) => keyResolver.resolveEd25519PublicKey(kid)
  const dsVerifier = new Ed25519MlsDsSignatureVerifier({ resolveEd25519PublicKey })
  const rosterVerifier = new Ed25519DeviceControlSignatureVerifier({ resolveEd25519PublicKey })
  const vaultDeliveryStore = new MemoryVaultDeliveryStore(rosterBackedVaultDeliveryAuthorizer(roster, rosterVerifier))
  const coreHandle = createBisetCoreFetchHandler({
    roster: { store: roster, verifier: rosterVerifier },
    mlsDelivery: { store: ds, verifier: dsVerifier, isLiveDevice: async () => true },
    vaultDeliveryStore,
  })
  return { anchor, ds, roster, vaultDeliveryStore, coreHandle }
}

describe('createNewIdentity', () => {
  test('genesis, device verificationMethod, self-group, roster, and KeyPackage pool all land', async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

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

describe('restoreIdentity', () => {
  test('a second device joins the existing identity from its recovery phrase', async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const created = await createNewIdentity(memoryIdentityRecordStore(), memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN,
      })
      const mnemonic = seedToMnemonic(created.masterSeed)

      const restoreRecordStore = memoryIdentityRecordStore()
      const restored = await restoreIdentity(restoreRecordStore, memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, mnemonic, deliveryFloorForNewDevice: async () => '0',
      })

      expect(restored.record.did).toBe(created.record.did)
      expect(restored.record.deviceKid).not.toBe(created.record.deviceKid)
      expect(new Set(memberKids(restored.selfGroupState, restored.record.did))).toEqual(new Set([created.record.deviceKid, restored.record.deviceKid]))
      expect(await restoreRecordStore.get(created.record.did)).toEqual(restored.record)

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('rejects a recovery phrase that does not control the identity at this domain', async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      await createNewIdentity(memoryIdentityRecordStore(), memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN,
      })
      const wrongMnemonic = seedToMnemonic(crypto.getRandomValues(new Uint8Array(32)))

      await expect(restoreIdentity(memoryIdentityRecordStore(), memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, mnemonic: wrongMnemonic, deliveryFloorForNewDevice: async () => '0',
      })).rejects.toThrow('does not control')

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('rejects when no identity exists at the domain', async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const mnemonic = seedToMnemonic(crypto.getRandomValues(new Uint8Array(32)))
      await expect(restoreIdentity(memoryIdentityRecordStore(), memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'nobody.test.example', coreBaseUrl: CORE_ORIGIN, mnemonic, deliveryFloorForNewDevice: async () => '0',
      })).rejects.toThrow('no identity found')

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })
})

describe('maintainSelfGroup', () => {
  test("the genesis device's own boot-time maintenance reflects a second device restored later", async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const deviceASelfGroupStore = memorySelfGroupStore()
      const created = await createNewIdentity(memoryIdentityRecordStore(), deviceASelfGroupStore, memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN,
      })
      const mnemonic = seedToMnemonic(created.masterSeed)

      const restored = await restoreIdentity(memoryIdentityRecordStore(), memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, mnemonic, deliveryFloorForNewDevice: async () => '0',
      })
      // Device B's own install attempt was rejected -- not yet reflected.
      expect(await roster.isTrustedDevice(created.record.did, restored.record.deviceKid!)).toBe(false)

      // Device A's own boot-time maintenance (main.ts's bootClient) catches
      // up on device B's commit and reflects it.
      const state = await maintainSelfGroup(deviceASelfGroupStore, memoryKeyPackageStore(), created.record, { coreBaseUrl: CORE_ORIGIN })
      expect(new Set(memberKids(state!, created.record.did))).toEqual(new Set([created.record.deviceKid, restored.record.deviceKid]))
      expect(await roster.isTrustedDevice(created.record.did, restored.record.deviceKid!)).toBe(true)

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('reflects a device restored after real vault content exists with the CURRENT latestSeq, not 0', async () => {
    const { anchor, ds, roster, vaultDeliveryStore, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const deviceASelfGroupStore = memorySelfGroupStore()
      const created = await createNewIdentity(memoryIdentityRecordStore(), deviceASelfGroupStore, memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN,
      })

      // Device A appends two vault-delivery items before device B ever exists.
      for (let i = 0; i < 2; i++) {
        const payload = new TextEncoder().encode(`item-${i}`)
        const append = {
          version: 1 as const, identityId: created.record.did, appendId: `evt-${i}`,
          payload, payloadHash: sha256Bytes(payload), senderDeviceId: created.record.deviceKid!, sentAt: new Date().toISOString(),
        }
        await vaultDeliveryStore.append({ ...append, signature: await ed25519.sign(vaultDeliveryAppendSigningBytes(append), (await deviceASelfGroupStore.load(created.record.did))!.state.signaturePrivateKey) })
      }

      const mnemonic = seedToMnemonic(created.masterSeed)
      const restored = await restoreIdentity(memoryIdentityRecordStore(), memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, mnemonic, deliveryFloorForNewDevice: async () => '0',
      })

      await maintainSelfGroup(deviceASelfGroupStore, memoryKeyPackageStore(), created.record, { coreBaseUrl: CORE_ORIGIN })
      expect(await roster.isTrustedDevice(created.record.did, restored.record.deviceKid!)).toBe(true)
      // NOT '0' -- device B's floor must be the seq AFTER the two items device
      // A already appended, so it never gets handed history predating it.
      expect(await roster.deliveryFloor(created.record.did, restored.record.deviceKid!)).toBe('2')

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test("self-grants a re-wrap of this identity's own segments when reflecting another device advances the epoch", async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const deviceASelfGroupStore = memorySelfGroupStore()
      const created = await createNewIdentity(memoryIdentityRecordStore(), deviceASelfGroupStore, memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN,
      })

      // Device A mints an active segment (and its wrap) at whatever epoch its
      // own genesis left it at -- before device B ever exists.
      const wraps = memoryWrapStore()
      const segments = memorySegmentStore()
      const boundary = buildVaultCryptoBoundary(wraps, segments, deviceASelfGroupStore, created.record)
      const minted = await boundary.activeSegment()
      const epochBefore = mlsEpoch(epochOf((await deviceASelfGroupStore.load(created.record.did))!.state))
      expect((await segments.allSegments(created.record.did))[0]!.epoch).toBe(epochBefore)

      const mnemonic = seedToMnemonic(created.masterSeed)
      const restored = await restoreIdentity(memoryIdentityRecordStore(), memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, mnemonic, deliveryFloorForNewDevice: async () => '0',
      })

      // Device A's own boot-time maintenance reflects device B's join, which
      // advances device A's own epoch -- and must self-grant a re-wrap of the
      // segment minted above before its old-epoch exporter secret is gone
      // for good.
      const state = await maintainSelfGroup(deviceASelfGroupStore, memoryKeyPackageStore(), created.record, {
        coreBaseUrl: CORE_ORIGIN, wraps, segments,
      })
      expect(new Set(memberKids(state!, created.record.did))).toEqual(new Set([created.record.deviceKid, restored.record.deviceKid]))
      const epochAfter = mlsEpoch(epochOf(state!))
      expect(epochAfter).not.toBe(epochBefore)

      // The segment record itself now tracks the new epoch...
      const record = (await segments.allSegments(created.record.did)).find(s => s.segmentId === minted.segmentId)!
      expect(record.epoch).toBe(epochAfter)

      // ...and the SegmentKey is still resolvable, unwrapping to the exact
      // same bytes minted before the epoch advanced. A fresh boundary
      // confirms this reads through `deviceASelfGroupStore`'s CURRENT state,
      // not anything cached on the original boundary.
      const boundaryAfter = buildVaultCryptoBoundary(wraps, segments, deviceASelfGroupStore, created.record)
      const resolved = await boundaryAfter.resolver.resolveSegmentKey(created.record.did, minted.segmentId)
      expect(resolved).toEqual(minted.segmentKey)

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('is a no-op with no stored self-group state', async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const record: IdentityRecord = { did: 'did:web:nobody.test.example', deviceKid: 'did:web:nobody.test.example#device-a', rootPublicKey: '', rootPrivateKey: '' }
      const state = await maintainSelfGroup(memorySelfGroupStore(), memoryKeyPackageStore(), record, { coreBaseUrl: CORE_ORIGIN })
      expect(state).toBeUndefined()

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })
})

// Minimal DidCommCredentialReader/Sink harness -- same shape as
// test/protocol/enable-openpgp.test.ts's own harness(), for the same reason:
// enableDidComm's DIDComm keyAgreement key is identity-shared (2026-08-27
// redesign), read/written through the vault rather than derived locally.
// `shared` lets two "devices" see the SAME underlying objects/events maps,
// simulating a real vault-delivery sync having already caught up.
function sharedDidCommVault(): { objects: Map<string, any>; events: any[]; segmentKey: Uint8Array } {
  return { objects: new Map(), events: [], segmentKey: createSegmentKey() }
}

async function didCommHarness(identityId: string, deviceId: string, shared: ReturnType<typeof sharedDidCommVault>, signer: VaultEventSigner) {
  const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(7), shared.segmentKey, { identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: deviceId, grantedAt: '2026-08-25T00:00:00.000Z' }, signer)
  let actorSeq = 0
  const committer = {
    async commitLocalMutation(input: any) {
      for (const object of input.objects) shared.objects.set(object.objectId, object)
      shared.events.push(...input.events)
      return 'committed' as const
    },
  }
  const reader = new DidCommCredentialReader({
    identityId,
    objects: { async readObject(_id: string, objectId: string) { return shared.objects.get(objectId) } },
    events: { async readCredentialEvents() { return shared.events.map(event => ({ ...event })) } },
    segmentKeys: { async resolveSegmentKey() { return shared.segmentKey.slice() } },
    verifier: signer,
  })
  const sink = new DidCommCredentialVaultSink({
    identityId, actorDeviceId: deviceId,
    async nextActorSeq() { return ++actorSeq },
    async initialParents() { return shared.events.length ? [shared.events.at(-1)!.id] : [] },
    async activeSegment() { return { segmentId: 'segment-1', segmentKey: shared.segmentKey, keyWraps: [wrap] } },
    async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } },
    signer, committer,
  })
  return { reader, sink }
}

// Same signing bytes regardless of deviceId, so two "devices" sharing one
// vault can each verify the other's events -- only `deviceId` differs.
function didCommTestSigner(deviceId: string): VaultEventSigner {
  return {
    deviceId,
    async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
    async verify(_deviceId, bytes, signature) {
      const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
      return expected.length === signature.length && expected.every((b, i) => b === signature[i])
    },
  }
}

describe('enableDidComm', () => {
  test('a second device adopts the first device\'s already-synced shared credential instead of minting a competing one', async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const deviceARecordStore = memoryIdentityRecordStore()
      const created = await createNewIdentity(deviceARecordStore, memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN,
      })
      const mnemonic = seedToMnemonic(created.masterSeed)

      const deviceBRecordStore = memoryIdentityRecordStore()
      const restored = await restoreIdentity(deviceBRecordStore, memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, mnemonic, deliveryFloorForNewDevice: async () => '0',
      })

      // 2026-08-27 redesign: the DIDComm keyAgreement key is identity-shared
      // (vault/didcomm-credential.ts, same shape as the OpenPGP mail
      // credential) -- device A mints it once; device B, sharing the SAME
      // underlying vault (simulating a real vault-delivery sync that has
      // already caught up), must ADOPT that exact key rather than mint a
      // competing one, and routing.json keeps exactly one keyAgreement entry
      // (replaced wholesale on each publish, never merged with a "prior
      // device's" entry -- there is no such thing anymore).
      const shared = sharedDidCommVault()
      const { reader: readerA, sink: sinkA } = await didCommHarness(created.record.did, 'device-a', shared, didCommTestSigner('device-a'))
      const { reader: readerB, sink: sinkB } = await didCommHarness(created.record.did, 'device-b', shared, didCommTestSigner('device-b'))

      const updatedA = await enableDidComm(deviceARecordStore, created.record, readerA, sinkA, { coreBaseUrl: CORE_ORIGIN })
      expect(updatedA.didCommKid).toBeDefined()
      const updatedB = await enableDidComm(deviceBRecordStore, restored.record, readerB, sinkB, { coreBaseUrl: CORE_ORIGIN })
      expect(updatedB.didCommKid).toBe(updatedA.didCommKid)
      expect(updatedB.didCommX25519PrivateKey).toBe(updatedA.didCommX25519PrivateKey)

      const routing = await fetchRouting(created.record.did, globalThis.fetch)
      const kids = (routing?.keyAgreementVerificationMethod ?? []).map(vm => vm.id)
      expect(kids).toEqual([updatedA.didCommKid])

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })

  test('is idempotent: a record that already has a didCommKid does not regenerate one', async () => {
    const { anchor, ds, roster, coreHandle } = setupCore()

    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle)
    try {
      const recordStore = memoryIdentityRecordStore()
      const created = await createNewIdentity(recordStore, memorySelfGroupStore(), memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN,
      })
      const { reader, sink } = await didCommHarness(created.record.did, 'device-a', sharedDidCommVault(), didCommTestSigner('device-a'))
      const first = await enableDidComm(recordStore, created.record, reader, sink, { coreBaseUrl: CORE_ORIGIN })
      const second = await enableDidComm(recordStore, first, reader, sink, { coreBaseUrl: CORE_ORIGIN })
      expect(second.didCommKid).toBe(first.didCommKid)
      expect(second.didCommX25519PrivateKey).toBe(first.didCommX25519PrivateKey)

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
