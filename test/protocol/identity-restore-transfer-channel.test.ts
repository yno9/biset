// Channel-level security properties of peer restore transfer, against a
// REAL MLS self group (not the trivial signer fixtures restore-transfer.test.ts
// / restore-transfer-receiver.test.ts use) -- PLAN.md §4.3's remaining "stale
// grant / removed requester / replay" gap. Replay itself (an earlier chunk
// resent after the session is already complete) is covered in
// restore-transfer-receiver.test.ts, which needs no real MLS state; this
// file covers the two properties that DO depend on live self-group
// membership: a grant whose epoch has been superseded, and a grant signed
// by a device the self group has since removed.
import { describe, expect, test } from 'bun:test'
import { buildRestoreTransferSource, buildRestoreTransferVerifier } from '../../src/identity/bootstrap.ts'
import {
  confirmCommit, createMlsGroup, epochOf, exportSecret, generateOwnKeyPackage, groupInfoForExternalJoin,
  joinGroupExternally, processIncoming, rekey, removeMembers,
} from '../../src/mls/group.ts'
import { MlsMembershipSegmentKeyWrapSigner } from '../../src/mls/segment-key-membership.ts'
import { selfGroupIdHex } from '../../src/mls/self-group.ts'
import { deriveVaultEpochKey } from '../../src/mls/vault-epoch.ts'
import { createVaultEvent } from '../../src/vault/events.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/vault/objects.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createRestoreTransferChunk, verifyRestoreTransferChunk } from '../../src/vault/restore-transfer.ts'
import { mlsEpoch } from '../../src/protocol/ids.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultRecordReader } from '../../src/vault/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const deviceKid = `${identityId}#device-a`
const deviceBKid = `${identityId}#device-b`

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

function memoryRecordReader(events: VaultEventV1[], objects: VaultObjectV1[]): VaultRecordReader {
  return {
    async readVaultEvents() { return events as (VaultEventV1 & { identityId: string })[] },
    async readVaultObjects() { return objects as (VaultObjectV1 & { identityId: string })[] },
  }
}

describe('peer restore transfer channel security', () => {
  test('a wrap for a superseded epoch is rejected once the source has rekeyed past it', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    let state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)
    const staleEpoch = mlsEpoch(epochOf(state))

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()

    // Device A already has a segment (with a genuine current-epoch wrap of
    // its own) from before this restore transfer -- minted directly here,
    // same as identity-restore-transfer-source.test.ts.
    const segmentKey = createSegmentKey()
    const loadState = async () => state
    const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)
    const vek = await deriveVaultEpochKey({ selfGroupId: selfGroupIdHex(identityId), epoch: staleEpoch, exportSecret: (label, ctx, len) => exportSecret(state, label, ctx, len) })
    await wraps.writeSegmentKeyWrap(await createSegmentKeyWrap(vek, segmentKey, {
      identityId, selfGroupId: selfGroupIdHex(identityId), segmentId: 'segment-1',
      sourceEpoch: staleEpoch, recipientEpoch: staleEpoch, grantorDeviceId: deviceKid, grantedAt: new Date().toISOString(),
    }, signer))

    const plaintext = new TextEncoder().encode('hello from device A')
    const object = await encryptVaultObject(segmentKey, { segmentId: 'segment-1', plaintext, aad: new TextEncoder().encode('aad') })
    const event = await createVaultEvent({
      identityId, actorDeviceId: deviceKid, actorSeq: 1, kind: 'message.add', targetIds: ['msg-1'], objectRefs: [object.objectId], parents: [], createdAt: new Date().toISOString(),
    }, signer)
    const records = memoryRecordReader([event], [object])

    // Grant a genuine wrap for the CURRENT (staleEpoch) epoch first...
    const source = buildRestoreTransferSource(records, wraps, selfGroupStore, record)
    const sourceManifest = await source.manifest(identityId)
    const requesterManifest = buildVaultManifest(identityId, [], [], new Date().toISOString())
    const staleChunk = await createRestoreTransferChunk(source, requesterManifest, undefined, staleEpoch)
    expect(staleChunk.keyWraps).toHaveLength(1)
    expect(staleChunk.keyWraps[0]!.recipientEpoch).toBe(staleEpoch)

    // ...then the self group rekeys (an ordinary MLS commit, no removal
    // involved) and device A reflects the new epoch locally.
    const result = await rekey(state)
    confirmCommit(result)
    state = result.state
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)
    const currentEpoch = mlsEpoch(epochOf(state))
    expect(currentEpoch).not.toBe(staleEpoch)

    // The requester claims the NEW epoch (its own real current one), but the
    // frame's own wrap is still stamped with the OLD, now-superseded epoch --
    // this must fail regardless of whether the grantor is still a member.
    const verifier = buildRestoreTransferVerifier(selfGroupStore, identityId)
    const ok = await verifyRestoreTransferChunk(staleChunk, sourceManifest, requesterManifest, currentEpoch, verifier)
    expect(ok).toBe(false)
  })

  test('a removed device cannot obtain a fresh restore grant for its own (frozen) epoch', async () => {
    // Device A creates the group; device B external-joins it -- both real
    // MLS operations, matching identity-vault-crypto.test.ts's Remove test.
    const kpA = await generateOwnKeyPackage(deviceKid)
    let stateA = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kpA)
    const kpB = await generateOwnKeyPackage(deviceBKid)
    const joinResult = await joinGroupExternally(await groupInfoForExternalJoin(stateA), kpB)
    const stateB = joinResult.state
    stateA = (await processIncoming(stateA, joinResult.commit)).state
    const staleEpochForB = mlsEpoch(epochOf(stateB))

    const selfGroupStoreA = memorySelfGroupStore()
    await selfGroupStoreA.save(identityId, selfGroupIdHex(identityId), stateA)
    const recordA: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()

    const plaintext = new TextEncoder().encode('hello from device A')
    const object = await encryptVaultObject(createSegmentKey(), { segmentId: 'segment-1', plaintext, aad: new TextEncoder().encode('aad') })
    const loadStateA = async () => stateA
    const signerA = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadStateA)
    const event = await createVaultEvent({
      identityId, actorDeviceId: deviceKid, actorSeq: 1, kind: 'message.add', targetIds: ['msg-1'], objectRefs: [object.objectId], parents: [], createdAt: new Date().toISOString(),
    }, signerA)
    const records = memoryRecordReader([event], [object])
    const sourceA = buildRestoreTransferSource(records, wraps, selfGroupStoreA, recordA)

    // Device A removes device B -- B never receives or applies this commit,
    // its own `stateB`/epoch stays frozen at the pre-removal value, exactly
    // like a device that is simply never told anything again.
    const removeResult = await removeMembers(stateA, [deviceBKid])
    confirmCommit(removeResult)
    stateA = removeResult.state
    await selfGroupStoreA.save(identityId, selfGroupIdHex(identityId), stateA)
    expect(mlsEpoch(epochOf(stateA))).not.toBe(staleEpochForB)

    // B (still believing its own pre-removal epoch is current) asks A's
    // source for a grant against ITS OWN epoch -- A's grantor only ever
    // grants for A's OWN current epoch, which has moved on since the
    // removal, so this must be refused rather than silently handing B a
    // wrap for an epoch B (or anyone else) can still derive a VEK for.
    await expect(sourceA.readCurrentEpochWraps(identityId, ['segment-1'], staleEpochForB))
      .rejects.toThrow('not this device\'s own current epoch')
  })

  test('a wrap signed by a now-removed grantor no longer verifies, even though the signature itself is valid', async () => {
    const kpA = await generateOwnKeyPackage(deviceKid)
    let stateA = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kpA)
    const kpB = await generateOwnKeyPackage(deviceBKid)
    const joinResult = await joinGroupExternally(await groupInfoForExternalJoin(stateA), kpB)
    const stateB = joinResult.state
    stateA = (await processIncoming(stateA, joinResult.commit)).state
    const sharedEpoch = mlsEpoch(epochOf(stateA))
    expect(sharedEpoch).toBe(mlsEpoch(epochOf(stateB)))

    // Device B grants a wrap for the shared epoch WHILE still a member --
    // a legitimate grant at the moment it was signed.
    const vek = await deriveVaultEpochKey({
      selfGroupId: selfGroupIdHex(identityId), epoch: sharedEpoch,
      exportSecret: (label, ctx, len) => exportSecret(stateB, label, ctx, len),
    })
    const signerB = new MlsMembershipSegmentKeyWrapSigner(deviceBKid, async () => stateB)
    const wrap = await createSegmentKeyWrap(vek, createSegmentKey(), {
      identityId, selfGroupId: selfGroupIdHex(identityId), segmentId: 'segment-1',
      sourceEpoch: sharedEpoch, recipientEpoch: sharedEpoch, grantorDeviceId: deviceBKid, grantedAt: new Date().toISOString(),
    }, signerB)

    const selfGroupStoreA = memorySelfGroupStore()
    await selfGroupStoreA.save(identityId, selfGroupIdHex(identityId), stateA)
    const verifierBeforeRemoval = buildRestoreTransferVerifier(selfGroupStoreA, identityId)
    expect(await verifierBeforeRemoval.verifyCurrentEpochWrap(wrap)).toBe(true)

    // A removes B. The wrap B already signed is untouched (SegmentKeyWraps
    // are immutable, signed objects), but verification always checks
    // CURRENT membership, not membership at grant time.
    const removeResult = await removeMembers(stateA, [deviceBKid])
    confirmCommit(removeResult)
    stateA = removeResult.state
    await selfGroupStoreA.save(identityId, selfGroupIdHex(identityId), stateA)

    const verifierAfterRemoval = buildRestoreTransferVerifier(selfGroupStoreA, identityId)
    expect(await verifierAfterRemoval.verifyCurrentEpochWrap(wrap)).toBe(false)
  })
})
