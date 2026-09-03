// End-to-end: buildRestoreTransferVerifier against a real MLS self group --
// confirms PLAN.md §4.3's "actual MLS grant verification" is wired:
// RestoreTransferVerifier's eventVerifier and verifyCurrentEpochWrap both
// accept a real event/wrap from a current self-group member and reject one
// from a device that was never in the group.
import { describe, expect, test } from 'bun:test'
import { buildRestoreTransferVerifier } from '../../src/identity/bootstrap.ts'
import { createMlsGroup, generateOwnKeyPackage, memberKids } from '../../src/mls/group.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'
import { MlsMembershipSegmentKeyWrapSigner } from '../../src/mls/segment-key-membership.ts'
import { createVaultEvent, verifyVaultEvent } from '../../src/vault/events.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import { mlsEpoch } from '../../src/protocol/ids.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { ClientState } from '../../src/mls/vendor/index.ts'

const identityId = 'did:web:alice.example'
const selfGroupId = 'test-self-group'
const device = await mlsDeviceFixture(identityId)
const deviceKid = device.kid

function memorySelfGroupStore(state: ClientState): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>([[identityId, { selfGroupId: selfGroupId, state }]])
  return {
    async save(id, selfGroupId, s) { rows.set(id, { selfGroupId, state: s }) },
    async load(id) { return rows.get(id) },
  }
}

describe('buildRestoreTransferVerifier', () => {
  test('accepts an event and a SegmentKeyWrap from a real current self-group member', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(new TextEncoder().encode(selfGroupId), kp)
    const selfGroupStore = memorySelfGroupStore(state)
    const loadState = async () => (await selfGroupStore.load(identityId))!.state
    const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)

    const verifier = buildRestoreTransferVerifier(selfGroupStore, identityId)

    const event = await createVaultEvent({
      identityId, actorDeviceId: deviceKid, actorSeq: 1, kind: 'message.add',
      targetIds: ['msg-1'], objectRefs: ['obj-1'], parents: [], createdAt: new Date().toISOString(),
    }, signer)
    expect(await verifyVaultEvent(event, verifier.eventVerifier)).toBe(true)

    const { epochOf } = await import('../../src/mls/group.ts')
    const { deriveVaultEpochKey } = await import('../../src/mls/vault-epoch.ts')
    const { exportSecret } = await import('../../src/mls/group.ts')
    const epoch = mlsEpoch(epochOf(state))
    const vek = await deriveVaultEpochKey({ selfGroupId: selfGroupId, epoch, exportSecret: (label, ctx, len) => exportSecret(state, label, ctx, len) })
    const wrap = await createSegmentKeyWrap(vek, crypto.getRandomValues(new Uint8Array(32)), {
      identityId, selfGroupId: selfGroupId, segmentId: 'segment-1',
      sourceEpoch: epoch, recipientEpoch: epoch, grantorDeviceId: deviceKid, grantedAt: new Date().toISOString(),
    }, signer)
    expect(await verifier.verifyCurrentEpochWrap(wrap)).toBe(true)
  })

  test('rejects an event actor and a wrap grantor that were never in the self group', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(new TextEncoder().encode(selfGroupId), kp)
    const selfGroupStore = memorySelfGroupStore(state)
    expect(memberKids(state, identityId)).toEqual([deviceKid])

    const verifier = buildRestoreTransferVerifier(selfGroupStore, identityId)

    const strangerKid = `${identityId}#not-a-member`
    const forged = { verify: async () => true }
    const strangerEvent = await createVaultEvent({
      identityId, actorDeviceId: strangerKid, actorSeq: 1, kind: 'message.add',
      targetIds: ['msg-1'], objectRefs: ['obj-1'], parents: [], createdAt: new Date().toISOString(),
    }, { deviceId: strangerKid, sign: async bytes => bytes, verify: forged.verify })
    expect(await verifyVaultEvent(strangerEvent, verifier.eventVerifier)).toBe(false)
  })
})
