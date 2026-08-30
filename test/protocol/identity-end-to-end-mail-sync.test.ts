// The capstone integration test this session's piecewise work never tied
// together: two REAL devices of one identity, a real Coordinator MLS DS plus
// a separately composed SQLite roster endpoint (same as
// identity-bootstrap.test.ts), device A creates an identity and writes a
// local mail message through the real production write path
// (VaultBackedLocalJmapMutationSink + buildVaultCryptoBoundary's real MLS
// signer), the packed delivery outbox is appended to core over real HTTP
// (CoreVaultDeliveryTransport), and device B -- added later via
// restoreIdentity, reflected into the roster by A's own boot-time
// maintainSelfGroup -- pulls it over real HTTP and projects it with its own
// real MLS verifier (buildVaultDeliveryProjector). Every prior test in this
// suite exercises one or two of these pieces in isolation; this is the only
// one that proves the whole create -> write -> deliver -> restore -> project
// path actually interoperates end to end.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createBisetCoreFetchHandler } from '../../src/core/app.ts'
import { SqliteMlsDeliveryService } from '../../src/coordinator/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/coordinator/mls-delivery-authorizer.ts'
import { createMlsDeliveryHttpHandler } from '../../src/coordinator/mls-delivery-http.ts'
import { MemoryVaultDeliveryStore } from '../../src/core/mediation/vault-delivery-store.ts'
import { SqliteTrustedDeviceRoster } from '../../src/core/identity/sqlite-device-roster.ts'
import { Ed25519DeviceControlSignatureVerifier } from '../../src/core/identity/ed25519-device-control-verifier.ts'
import { rosterBackedVaultDeliveryAuthorizer } from '../../src/core/identity/authorizers.ts'
import { WebvhSigningKeyResolver } from '../../src/core/identity/webvh-signing-key-resolver.ts'
import { buildVaultCryptoBoundary, buildVaultDeliveryProjector, createNewIdentity, maintainSelfGroup, restoreIdentity } from '../../src/identity/bootstrap.ts'
import { seedToMnemonic } from '../../src/identity/seed.ts'
import { setMlsAuthService } from '../../src/mls/group.ts'
import { defaultAuthenticationService } from '../../src/mls/vendor/index.ts'
import { CoreVaultDeliveryTransport } from '../../src/vault/core-delivery-transport.ts'
import { buildMailMessageAdd } from '../../src/vault/mail-message.ts'
import { decodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import { VaultBackedLocalJmapMutationSink, type LocalVaultMutationCommitter } from '../../src/local-jmap/vault-mutation-sink.ts'
import { LocalJmapGateway, LocalJmapTransport, MemoryLocalJmapReadModel, type LocalJmapSnapshot } from '../../src/local-jmap/gateway.ts'
import { deliverySeq } from '../../src/protocol/ids.ts'
import { vaultDeliveryPullSigningBytes } from '../../src/protocol/signing.ts'
import { fakeAnchor } from './support/webvh-log-fixture.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { MlsKeyPackageStore } from '../../src/mls/keypackage-store.ts'
import type { IdentityRecord, IdentityRecordStore } from '../../src/identity/record-store.ts'
import type { OwnKeyPackage } from '../../src/mls/group.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { SegmentKeyWrapV1, VaultDeliveryPullV1 } from '../../src/protocol/vault.ts'

const dsPath = `/tmp/biset-e2e-mail-ds-${process.pid}-${Date.now()}.sqlite`
const rosterPath = `/tmp/biset-e2e-mail-roster-${process.pid}-${Date.now()}.sqlite`
const CORE_ORIGIN = 'https://core.test.example'
const COORDINATOR_ORIGIN = 'https://coordinator.test.example'

afterEach(() => {
  for (const base of [dsPath, rosterPath]) {
    for (const suffix of ['', '-wal', '-shm']) {
      try { rmSync(`${base}${suffix}`) } catch {}
    }
  }
  setMlsAuthService(defaultAuthenticationService)
})

function memoryIdentityRecordStore(): IdentityRecordStore {
  const rows = new Map<string, IdentityRecord>()
  return { async get(did) { return rows.get(did) }, async put(record) { rows.set(record.did, record) }, async list() { return [...rows.values()] } }
}

function memorySelfGroupStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return { async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) }, async load(id) { return rows.get(id) } }
}

function memoryWrapStore(): SegmentKeyWrapReader & SegmentKeyWrapWriter {
  const rows = new Map<string, SegmentKeyWrapV1>()
  const key = (id: string, segmentId: string, epoch: string) => `${id} ${segmentId} ${epoch}`
  return {
    async readSegmentKeyWrap(id, segmentId, epoch) { return rows.get(key(id, segmentId, epoch)) },
    async writeSegmentKeyWrap(wrap) { rows.set(key(wrap.identityId, wrap.segmentId, wrap.recipientEpoch), wrap) },
  }
}

function memorySegmentStore(): ActiveVaultSegmentStore {
  const rows: VaultSegmentRecord[] = []
  return {
    async currentSegment(id) { return rows.find(r => r.identityId === id && !r.sealed) },
    async allSegments(id) { return rows.filter(r => r.identityId === id) },
    async sealAndActivateSegment(next) {
      for (const row of rows) if (row.identityId === next.identityId && !row.sealed) row.sealed = true
      rows.push({ ...next })
    },
    async recordSegmentRewrapped(id, segmentId, epoch) {
      const row = rows.find(r => r.identityId === id && r.segmentId === segmentId)
      if (!row) throw new Error('no such segment')
      row.epoch = epoch
    },
  }
}

function memoryKeyPackageStore(): MlsKeyPackageStore {
  const byRef = new Map<string, OwnKeyPackage>()
  return {
    async mint(kid, credential, signaturePrivateKey, count) {
      const { generateOwnKeyPackage, keyPackageRefOf } = await import('../../src/mls/group.ts')
      const minted: OwnKeyPackage[] = []
      for (let i = 0; i < count; i++) {
        const own = await generateOwnKeyPackage(credential, signaturePrivateKey)
        byRef.set(await keyPackageRefOf(own.publicPackage), own)
        minted.push(own)
      }
      return minted
    },
    async takeForWelcome() { throw new Error('not used by this test') },
  }
}

function combinedFetch(anchorFetch: typeof fetch, coreHandle: (request: Request) => Promise<Response>, mlsHandle: (request: Request) => Promise<Response>): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init)
    if (request.url.startsWith(COORDINATOR_ORIGIN)) return mlsHandle(request)
    if (request.url.startsWith(CORE_ORIGIN)) return coreHandle(request)
    return anchorFetch(input, init)
  }) as typeof fetch
}

function setupCore() {
  const anchor = fakeAnchor()
  const ds = SqliteMlsDeliveryService.open(dsPath)
  const roster = SqliteTrustedDeviceRoster.open(rosterPath)
  const keyResolver = new WebvhSigningKeyResolver()
  const resolveEd25519PublicKey = (kid: string, identityId: string, credential: Uint8Array) => keyResolver.resolveEd25519PublicKey(kid, identityId, credential)
  const dsVerifier = new Ed25519MlsDsSignatureVerifier({ resolveEd25519PublicKey })
  const mlsHandle = createMlsDeliveryHttpHandler(ds, dsVerifier, async () => true)
  const rosterVerifier = new Ed25519DeviceControlSignatureVerifier({ resolveEd25519PublicKey })
  const vaultDeliveryStore = new MemoryVaultDeliveryStore(rosterBackedVaultDeliveryAuthorizer(roster, rosterVerifier))
  const coreHandle = createBisetCoreFetchHandler({
    roster: { store: roster, verifier: rosterVerifier },
    vaultDeliveryStore,
  })
  return { anchor, ds, roster, vaultDeliveryStore, coreHandle, mlsHandle }
}

describe('end-to-end: create -> write -> deliver -> restore -> project', () => {
  test('device B, added after device A already wrote mail, receives and projects it through real core HTTP and real MLS', async () => {
    const { anchor, ds, roster, coreHandle, mlsHandle } = setupCore()
    const realFetch = globalThis.fetch
    globalThis.fetch = combinedFetch(anchor.fetch, coreHandle, mlsHandle)
    try {
      // Device A creates the identity and writes a mail message locally.
      const selfGroupStoreA = memorySelfGroupStore()
      const created = await createNewIdentity(memoryIdentityRecordStore(), selfGroupStoreA, memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, mlsDeliveryBaseUrl: COORDINATOR_ORIGIN,
      })
      const wrapsA = memoryWrapStore()
      // The SAME segments store instance must back both buildVaultCryptoBoundary
      // and maintainSelfGroup below -- self-grant rewrap can only find A's
      // segment to re-wrap it if both look at the same durable store, exactly
      // like the real IndexedDbVaultStore would be for both call sites.
      const segmentsA = memorySegmentStore()
      const boundaryA = buildVaultCryptoBoundary(wrapsA, segmentsA, selfGroupStoreA, created.record)

      let committed: Record<string, unknown> | undefined
      const committer: LocalVaultMutationCommitter = {
        async commitLocalMutation(input) { committed = input as unknown as Record<string, unknown>; return 'committed' },
      }
      let sequence = 0
      const sink = new VaultBackedLocalJmapMutationSink({
        accountId: `biset:${created.record.did}`,
        identityId: created.record.did,
        actorDeviceId: created.record.deviceKid!,
        async nextActorSeq() { sequence += 1; return sequence },
        async initialParents() { return [] },
        activeSegment: () => boundaryA.activeSegment(),
        signer: boundaryA.signer,
        committer,
        now: () => new Date('2026-08-24T00:00:00.000Z'),
      })
      // emailSetToVaultMutationIntents only supports update/destroy of an
      // EXISTING email (message.add creation is a separate, mail-ingress-only
      // path -- see local-jmap/mutations.ts's own note) -- so this writes a
      // message.add directly via buildMailMessageAdd against A's own active
      // segment, the same way a real mail-ingress endpoint would, then goes
      // through the ordinary Email/set keyword.set path for a second event
      // to prove the sink's OWN write path also lands in the same pack.
      const segment = await boundaryA.activeSegment()
      // Must precede the sink's own nextActorSeq() call below in the shared
      // counter -- both events share the same actorDeviceId and createdAt,
      // so the reducer's LWW sort (createdAt -> actorDeviceId -> actorSeq ->
      // id) falls through to actorSeq to order message.add before
      // keyword.set. Leaving this at a fixed actorSeq that happens to
      // collide with the sink's own first call would make the two events'
      // relative order depend on their (randomly-keyed, therefore
      // unpredictable) content-hash ids instead -- and the reducer skips a
      // keyword.set delivered before its email exists.
      sequence += 1
      const { metadataObject, rawRfc5322Object, event: addEvent } = await buildMailMessageAdd(
        {
          email: { id: 'msg-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-24T00:00:00.000Z' },
          rawRfc5322: new TextEncoder().encode('Subject: hello from A\r\n\r\nhi B'),
        },
        { identityId: created.record.did, actorDeviceId: created.record.deviceKid!, actorSeq: sequence, parents: [], segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt: '2026-08-24T00:00:00.000Z' },
        boundaryA.signer,
      )

      const model = new MemoryLocalJmapReadModel({
        state: 'state-0',
        mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 1, unreadEmails: 1 }],
        emails: [{ id: 'msg-1', blobId: rawRfc5322Object.objectId, threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-24T00:00:00.000Z' }],
      })
      const transport = new LocalJmapTransport(new LocalJmapGateway({ accountId: `biset:${created.record.did}`, identityId: created.record.did, readModel: model, mutationSink: sink }))
      await transport.call([{ name: 'Email/set', arguments: { accountId: `biset:${created.record.did}`, update: { 'msg-1': { keywords: { '$seen': true } } } }, callId: 'set-1' }])

      // Device B is added BEFORE the pack is built, from A's recovery
      // phrase -- this advances A's own self-group epoch once A's own
      // boot-time maintenance reflects B, which is exactly why the pack
      // must be assembled AFTER that (below), using a freshly re-wrapped
      // current-epoch keyWrap rather than the one segment.keyWraps captured
      // at mint time, before B existed.
      const mnemonic = seedToMnemonic(created.masterSeed)
      const selfGroupStoreB = memorySelfGroupStore()
      const restored = await restoreIdentity(memoryIdentityRecordStore(), selfGroupStoreB, memoryKeyPackageStore(), {
        domain: 'y.test.example', coreBaseUrl: CORE_ORIGIN, mlsDeliveryBaseUrl: COORDINATOR_ORIGIN, mnemonic, signMnemonic: mnemonic, deliveryFloorForNewDevice: async () => '0',
      })
      // B's Root + current-Sign credential reflects its accepted external
      // commit immediately. A still performs boot-time maintenance to catch
      // up its local MLS state and self-grant the new-epoch wrap.
      expect(await roster.isTrustedDevice(created.record.did, restored.record.deviceKid!)).toBe(true)
      await maintainSelfGroup(selfGroupStoreA, memoryKeyPackageStore(), created.record, {
        coreBaseUrl: CORE_ORIGIN, mlsDeliveryBaseUrl: COORDINATOR_ORIGIN, wraps: wrapsA, segments: segmentsA,
      })
      expect(await roster.isTrustedDevice(created.record.did, restored.record.deviceKid!)).toBe(true)

      // Assemble the real shared-vault delivery pack: A's message.add PLUS
      // the sink's own keyword.set, exactly the shape a real device would
      // append after a local mutation batch -- using activeSegment() again
      // now, so the embedded keyWrap is the fresh, self-granted one for A's
      // CURRENT (post-reflect) epoch, not the stale pre-reflect one.
      const { encodeVaultDeliveryPack } = await import('../../src/vault/delivery-pack.ts')
      const currentSegment = await boundaryA.activeSegment()
      const payload = encodeVaultDeliveryPack({
        version: 1,
        identityId: created.record.did,
        objects: [
          { ...metadataObject, identityId: created.record.did },
          { ...rawRfc5322Object, identityId: created.record.did },
          ...(committed?.objects as Array<{ identityId: string }>),
        ],
        events: [addEvent, ...(committed?.events as Array<{ identityId: string }>)],
        keyWraps: currentSegment.keyWraps,
      })

      // A appends the pack to core over REAL HTTP, signed with its real MLS leaf key.
      const stateA = (await selfGroupStoreA.load(created.record.did))!.state
      const { vaultDeliveryAppendSigningBytes } = await import('../../src/protocol/signing.ts')
      const { sha256Bytes } = await import('../../src/protocol/canonical.ts')
      const appendTransport = new CoreVaultDeliveryTransport({ baseUrl: CORE_ORIGIN })
      const append = {
        version: 1 as const, identityId: created.record.did, appendId: 'append-1', payload, payloadHash: sha256Bytes(payload),
        senderDeviceId: created.record.deviceKid!, sentAt: '2026-08-24T00:01:00.000Z',
      }
      await appendTransport.append({ ...append, signature: ed25519.sign(vaultDeliveryAppendSigningBytes(append), stateA.signaturePrivateKey) })

      // Device B pulls the SAME item over REAL HTTP, verifies it with its
      // OWN real MLS state, and projects it -- no shared in-memory object
      // with device A anywhere in this half of the test.
      const pullTransport = new CoreVaultDeliveryTransport({ baseUrl: CORE_ORIGIN })
      const stateB = (await selfGroupStoreB.load(created.record.did))!.state
      const pull: Omit<VaultDeliveryPullV1, 'signature'> = {
        version: 1, identityId: created.record.did, recipientDeviceId: restored.record.deviceKid!, after: deliverySeq(0n), requestedAt: '2026-08-24T00:02:00.000Z',
      }
      const result = await pullTransport.pull({ ...pull, signature: ed25519.sign(vaultDeliveryPullSigningBytes(pull), stateB.signaturePrivateKey) })
      expect(result.kind).toBe('items')
      if (result.kind !== 'items') throw new Error('unreachable')
      expect(result.items).toHaveLength(1)

      const pack = decodeVaultDeliveryPack(result.items[0]!.payload)
      const baseSnapshot: LocalJmapSnapshot = { state: '0', mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 0, unreadEmails: 0 }], emails: [] }
      const projectorB = buildVaultDeliveryProjector(selfGroupStoreB, created.record.did, async () => baseSnapshot, restored.record.masterSeed)
      const projected = await projectorB.verifyAndProject(pack)

      expect(projected.projection.emails).toHaveLength(1)
      expect(projected.projection.emails[0]).toMatchObject({
        id: 'msg-1', threadId: 'thread-1', blobId: rawRfc5322Object.objectId, keywords: { '$seen': true },
      })

      ds.close()
      roster.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
