// PLAN.md §4.3's "projection rebuild" after a peer restore transfer: proves
// rebuildLocalJmapProjection (already implemented generically for §5.2,
// vault/projection-rebuild.ts) actually reconstructs the correct Local JMAP
// projection from records a REAL restore-transfer session committed --
// not just from records accumulated the ordinary way. No prior test
// combined these two: identity-restore-transfer-source.test.ts stops at
// "the requester can decrypt the transferred object," and
// identity-local-jmap-projection-rebuild.test.ts never went through a
// restore transfer to get its records.
import { describe, expect, test } from 'bun:test'
import { buildLocalJmapProjectionRebuild, buildRestoreTransferSource, buildRestoreTransferVerifier, buildVaultCryptoBoundary } from '../../src/identity/bootstrap.ts'
import { createMlsGroup, epochOf, generateOwnKeyPackage } from '../../src/mls/group.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'
import { MlsMembershipSegmentKeyWrapSigner } from '../../src/mls/segment-key-membership.ts'
import { buildMailMessageAdd } from '../../src/vault/mail-message.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createRestoreTransferChunk, verifyRestoreTransferChunk } from '../../src/vault/restore-transfer.ts'
import { receiveRestoreTransferChunk, type RestoreTransferChunkCommit, type RestoreTransferReceiverStore, type RestoreTransferSessionV1 } from '../../src/vault/restore-transfer-receiver.ts'
import { mlsEpoch } from '../../src/shared/protocol/ids.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultRecordReader, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../../src/shared/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const selfGroupId = 'test-self-group'
const device = await mlsDeviceFixture(identityId)
const deviceKid = device.kid

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
      if (!row) throw new Error('no such segment')
      row.epoch = epoch
    },
  }
}

/** The requester's own durable state after a restore transfer: raw records + session cursor, exactly what commitRestoreTransferChunk persists -- also usable directly as a VaultRecordReader/SegmentKeyWrapReader for rebuildLocalJmapProjection, same as the requester's real IndexedDbVaultStore would be. */
function memoryReceiverStore(): RestoreTransferReceiverStore & VaultRecordReader & SegmentKeyWrapReader {
  let session: RestoreTransferSessionV1 | undefined
  const events: VaultEventV1[] = []
  const objects: VaultObjectV1[] = []
  const wraps = new Map<string, SegmentKeyWrapV1>()
  const wrapKey = (id: string, segmentId: string, epoch: string) => `${id} ${segmentId} ${epoch}`
  return {
    async readRestoreTransferSession() { return session },
    async commitRestoreTransferChunk(input: RestoreTransferChunkCommit) {
      session = input.session
      events.push(...input.events)
      objects.push(...input.objects)
      for (const wrap of input.keyWraps) wraps.set(wrapKey(wrap.identityId, wrap.segmentId, wrap.recipientEpoch), wrap)
    },
    async readVaultEvents() { return events.map(event => ({ ...event, identityId })) },
    async readVaultObjects() { return objects.map(object => ({ ...object, identityId })) },
    async readSegmentKeyWrap(id, segmentId, epoch) { return wraps.get(wrapKey(id, segmentId, epoch)) },
  }
}

describe('projection rebuild after a real peer restore transfer', () => {
  test('reconstructs the correct Local JMAP projection from records a restore transfer actually committed', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(new TextEncoder().encode(selfGroupId), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupId, state)
    const epoch = mlsEpoch(epochOf(state))

    // The source device already has a real mail item.
    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
    const segment = await boundary.activeSegment()
    const loadState = async () => state
    const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)
    const { metadataObject, rawRfc5322Object, event } = await buildMailMessageAdd(
      {
        email: { id: 'msg-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: new Date().toISOString() },
        rawRfc5322: new TextEncoder().encode('Subject: hi\r\n\r\nhello'),
      },
      { identityId, actorDeviceId: deviceKid, actorSeq: 1, parents: [], segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt: new Date().toISOString() },
      signer,
    )
    const records: VaultRecordReader = {
      async readVaultEvents() { return [{ ...event, identityId }] },
      async readVaultObjects() { return [{ ...metadataObject, identityId }, { ...rawRfc5322Object, identityId }] },
    }
    const source = buildRestoreTransferSource(records, wraps, selfGroupStore, record)

    // A real restore-transfer round trip: manifest diff -> one chunk (small
    // dataset) -> verify -> commit into the requester's own durable store.
    const sourceManifest = await source.manifest(identityId)
    const requesterManifest = buildVaultManifest(identityId, [], [], new Date().toISOString())
    const chunk = await createRestoreTransferChunk(source, requesterManifest, undefined, epoch)
    expect(chunk.next).toBeUndefined()
    expect(chunk.events).toHaveLength(1)
    expect(chunk.objects).toHaveLength(2)

    const verifier = buildRestoreTransferVerifier(selfGroupStore, identityId)
    expect(await verifyRestoreTransferChunk(chunk, sourceManifest, requesterManifest, epoch, verifier)).toBe(true)

    const receiverStore = memoryReceiverStore()
    const result = await receiveRestoreTransferChunk(receiverStore, 'device-requester', chunk, sourceManifest, requesterManifest, epoch, verifier)
    expect(result.kind).toBe('committed')
    expect(result.session.completed).toBe(true)

    // Now rebuild: the requester's own projection store never received an
    // incremental fold (restore transfer never runs one, by design -- see
    // vault/projection-rebuild.ts's own doc comment) -- this is the ONLY
    // way its projection ever gets built.
    const projections = { rows: new Map<string, unknown>(), async readProjection(id: string) { return this.rows.get(id) }, async writeProjection(id: string, projection: unknown) { this.rows.set(id, projection) } }
    const rebuild = buildLocalJmapProjectionRebuild(receiverStore, receiverStore, projections, selfGroupStore, identityId)
    const projection = await rebuild()

    expect(projection.emails).toHaveLength(1)
    expect(projection.emails[0]).toMatchObject({ id: 'msg-1', threadId: 'thread-1', mailboxIds: { inbox: true }, blobId: rawRfc5322Object.objectId })
    expect(await projections.readProjection(identityId)).toEqual(projection)
  })
})
