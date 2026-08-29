// End-to-end: buildVaultDeliveryProjector against a real MLS self group --
// confirms PLAN.md §3.3/§4.2's "actual MLS wrap / event verify" for shared
// vault delivery is wired: a mutation record built with the same
// SegmentKey/wraps buildVaultCryptoBoundary's activeSegment() produces is
// packed, decoded, and correctly verified + decrypted + projected by
// VaultDeliveryProjector via a real MLS exporter secret -- not a hand-built
// fixture on either side.
import { describe, expect, test } from 'bun:test'
import { buildVaultCryptoBoundary, buildVaultDeliveryProjector } from '../../src/identity/bootstrap.ts'
import { createMlsGroup, generateOwnKeyPackage } from '../../src/mls/group.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'
import { MlsMembershipSegmentKeyWrapSigner } from '../../src/mls/segment-key-membership.ts'
import { selfGroupIdHex } from '../../src/mls/self-group.ts'
import { buildVaultMutation } from '../../src/vault/mutations.ts'
import { encodeVaultDeliveryPack, decodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'
import type { SegmentKeyWrapV1 } from '../../src/protocol/vault.ts'
import type { LocalJmapSnapshot } from '../../src/local-jmap/gateway.ts'

const identityId = 'did:web:alice.example'
const device = await mlsDeviceFixture(identityId)
const deviceKid = device.kid

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
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
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
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
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
