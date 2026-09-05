// End-to-end: buildVaultDeliveryProjector against a real MLS self group --
// confirms PLAN.md §3.3/§4.2's "actual MLS wrap / event verify" for shared
// vault delivery is wired: a mutation record built with the same
// SegmentKey/wraps buildWalletVaultCryptoBoundary's activeSegment() produces is
// packed, decoded, and correctly verified + decrypted + projected by
// VaultDeliveryProjector via a real MLS exporter secret -- not a hand-built
// fixture on either side.
import { describe, expect, test } from 'bun:test'
import { buildWalletVaultCryptoBoundary, buildVaultDeliveryProjector } from '../../src/client/identity/bootstrap.ts'
import { createMlsGroup, generateOwnKeyPackage } from '../../src/client/mimi/group.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'
import { MlsMembershipSegmentKeyWrapSigner } from '../../src/client/mimi/segment-key-membership.ts'
import { buildVaultMutation } from '../../src/client/store/vault/mutations.ts'
import { encodeVaultDeliveryPack, decodeVaultDeliveryPack } from '../../src/client/store/vault/delivery-pack.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/client/mimi/store.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from '../../src/client/store/vault/store.ts'
import type { SegmentKeyWrapV1 } from '../../src/shared/protocol/vault.ts'
import type { LocalJmapSnapshot } from '../../src/client/store/projection/gateway.ts'

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
    async currentSegment(identityId) { return rows.find(r => r.identityId === identityId && !r.sealed) },
    async sealAndActivateSegment(next) {
      for (const row of rows) if (row.identityId === next.identityId && !row.sealed) row.sealed = true
      rows.push({ ...next })
    },
  }
}

describe('buildVaultDeliveryProjector', () => {
  test('verifies and projects a real vault-delivery pack end to end', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(new TextEncoder().encode(selfGroupId), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupId, state)

    const record = { did: identityId, deviceKid }
    const wraps = memoryWrapStore()
    const boundary = buildWalletVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
    const segment = await boundary.activeSegment()

    const loadState = async () => (await selfGroupStore.load(identityId))!.state
    const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)
    const { object, event } = await buildVaultMutation(
      { kind: 'message.tombstone', targetIds: ['msg-1'], payload: { emailId: 'msg-1' } },
      { identityId, actorDeviceId: deviceKid, actorSeq: 1, parents: [], segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt: new Date().toISOString() },
      signer,
    )

    const payload = encodeVaultDeliveryPack({ version: 1, identityId, objects: [{ ...object, identityId }], events: [event], keyWraps: segment.keyWraps })
    const pack = decodeVaultDeliveryPack(payload)

    const baseSnapshot: LocalJmapSnapshot = { state: '0', mailboxes: [], emails: [] }
    const projector = buildVaultDeliveryProjector(selfGroupStore, identityId, async () => baseSnapshot)

    const derived = await projector.verifyAndProject(pack)
    expect(derived.checkpointId).toBeTruthy()
    expect(derived.projection.identityId).toBe(identityId)
    expect(derived.projection.emails).toEqual([])
  })

  test('rejects a pack whose event was signed by a device never in the self group', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(new TextEncoder().encode(selfGroupId), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupId, state)

    const record = { did: identityId, deviceKid }
    const wraps = memoryWrapStore()
    const boundary = buildWalletVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
    const segment = await boundary.activeSegment()

    const strangerKid = `${identityId}#not-a-member`
    const forgedSigner = { deviceId: strangerKid, sign: async (bytes: Uint8Array) => bytes, verify: async () => true }
    const { object, event } = await buildVaultMutation(
      { kind: 'message.tombstone', targetIds: ['msg-1'], payload: { emailId: 'msg-1' } },
      { identityId, actorDeviceId: strangerKid, actorSeq: 1, parents: [], segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt: new Date().toISOString() },
      forgedSigner,
    )

    const payload = encodeVaultDeliveryPack({ version: 1, identityId, objects: [{ ...object, identityId }], events: [event], keyWraps: segment.keyWraps })
    const pack = decodeVaultDeliveryPack(payload)
    const baseSnapshot: LocalJmapSnapshot = { state: '0', mailboxes: [], emails: [] }
    const projector = buildVaultDeliveryProjector(selfGroupStore, identityId, async () => baseSnapshot)

    await expect(projector.verifyAndProject(pack)).rejects.toThrow('event signature is invalid')
  })
})
