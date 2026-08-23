// End-to-end: buildLocalJmapProjectionRebuild against a real MLS self group --
// confirms PLAN.md §3.2/§5.2's "full projection rebuild" actually recomputes
// a Local JMAP projection from every event/object an identity has stored
// (not just one delivered pack, VaultDeliveryProjector's job) and persists
// it through VaultProjectionWriter -- including the brand-new-identity case
// where NOTHING has seeded a `vault_projection` row yet.
import { describe, expect, test } from 'bun:test'
import { buildLocalJmapProjectionRebuild, buildVaultCryptoBoundary } from '../../src/identity/bootstrap.ts'
import { createMlsGroup, generateOwnKeyPackage } from '../../src/mls/group.ts'
import { MlsMembershipSegmentKeyWrapSigner } from '../../src/mls/segment-key-membership.ts'
import { selfGroupIdHex } from '../../src/mls/self-group.ts'
import { buildMailMessageAdd } from '../../src/vault/mail-message.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultRecordReader, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const deviceKid = `${identityId}#device-a`

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
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
      if (!row) throw new Error('recordSegmentRewrapped: no such segment')
      row.epoch = epoch
    },
  }
}

function memoryRecordStore(): VaultRecordReader & { events: VaultEventV1[]; objects: VaultObjectV1[] } {
  const events: VaultEventV1[] = []
  const objects: VaultObjectV1[] = []
  return {
    events,
    objects,
    async readVaultEvents() { return events.map(event => ({ ...event, identityId })) },
    async readVaultObjects() { return objects.map(object => ({ ...object, identityId })) },
  }
}

function memoryProjectionStore(): { readProjection(id: string): Promise<unknown>; writeProjection(id: string, projection: unknown, jmapState: unknown): Promise<void> } {
  const rows = new Map<string, unknown>()
  return {
    async readProjection(id) { return rows.get(id) },
    async writeProjection(id, projection) { rows.set(id, projection) },
  }
}

describe('buildLocalJmapProjectionRebuild', () => {
  test('seeds an empty projection for a brand-new identity with no stored events', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const records = memoryRecordStore()
    const wraps = memoryWrapStore()
    const projections = memoryProjectionStore()
    const rebuild = buildLocalJmapProjectionRebuild(records, wraps, projections, selfGroupStore, identityId)

    expect(await projections.readProjection(identityId)).toBeUndefined()

    const projection = await rebuild()
    expect(projection).toEqual({ version: 1, identityId, state: projection.state, mailboxes: [], emails: [] })
    expect(projection.state).toBeTruthy()

    // The rebuild is the ONLY thing that seeds this identity's very first
    // vault_projection row -- confirm it actually persisted, not just returned.
    expect(await projections.readProjection(identityId)).toEqual(projection)
  })

  test('rebuilds the full projection from every stored message.add, matching a fresh replay', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
    const segment = await boundary.activeSegment()

    const loadState = async () => (await selfGroupStore.load(identityId))!.state
    const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)
    const { metadataObject, rawRfc5322Object, event } = await buildMailMessageAdd(
      {
        email: { id: 'msg-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: new Date().toISOString() },
        rawRfc5322: new TextEncoder().encode('Subject: hi\r\n\r\nhello'),
      },
      { identityId, actorDeviceId: deviceKid, actorSeq: 1, parents: [], segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt: new Date().toISOString() },
      signer,
    )

    const records = memoryRecordStore()
    records.events.push(event)
    records.objects.push(metadataObject, rawRfc5322Object)

    const projections = memoryProjectionStore()
    const rebuild = buildLocalJmapProjectionRebuild(records, wraps, projections, selfGroupStore, identityId)
    const projection = await rebuild()

    expect(projection.identityId).toBe(identityId)
    expect(projection.emails).toHaveLength(1)
    expect(projection.emails[0]!.id).toBe('msg-1')
    expect(projection.emails[0]!.blobId).toBe(rawRfc5322Object.objectId)
    expect(projection.emails[0]!.mailboxIds).toEqual({ inbox: true })
    expect(await projections.readProjection(identityId)).toEqual(projection)
  })

  test('rejects a rebuild whose event was signed by a device never in the self group', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
    const segment = await boundary.activeSegment()

    const strangerKid = `${identityId}#not-a-member`
    const forgedSigner = { deviceId: strangerKid, sign: async (bytes: Uint8Array) => bytes, verify: async () => true }
    const { metadataObject, rawRfc5322Object, event } = await buildMailMessageAdd(
      {
        email: { id: 'msg-1', threadId: 'thread-1', mailboxIds: {}, keywords: {}, receivedAt: new Date().toISOString() },
        rawRfc5322: new TextEncoder().encode('Subject: hi\r\n\r\nhello'),
      },
      { identityId, actorDeviceId: strangerKid, actorSeq: 1, parents: [], segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt: new Date().toISOString() },
      forgedSigner,
    )

    const records = memoryRecordStore()
    records.events.push(event)
    records.objects.push(metadataObject, rawRfc5322Object)

    const projections = memoryProjectionStore()
    const rebuild = buildLocalJmapProjectionRebuild(records, wraps, projections, selfGroupStore, identityId)
    await expect(rebuild()).rejects.toThrow('event signature is invalid')
    // A failed rebuild must not persist a half-verified projection.
    expect(await projections.readProjection(identityId)).toBeUndefined()
  })
})
