// End-to-end: buildVaultCryptoBoundary against a real MLS self group --
// confirms PLAN.md §4.2's "actual MLS VEK derivation / membership signer"
// is now wired: a SegmentKeyWrap signed/verified through the boundary's
// signer actually round-trips through createSegmentKeyWrap/unwrapSegmentKey
// with a VEK derived from the real self-group exporter secret, a grantor no
// longer in the group can no longer be verified, and activeSegment() mints
// a fresh (sealing the old) segment exactly when the self-group epoch moves.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { buildVaultCryptoBoundary, repairCurrentLocalSegmentKeyWraps } from '../../src/identity/bootstrap.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import {
  confirmCommit, createMlsGroup, epochOf, exportSecret, generateOwnKeyPackage, groupInfoForExternalJoin,
  joinGroupExternally, memberKids, processIncoming, rekey, removeMembers,
} from '../../src/mls/group.ts'
import { unwrapSegmentKey } from '../../src/vault/crypto.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'
import { selfGroupIdHex } from '../../src/mls/self-group.ts'
import { VAULT_STORAGE_EPOCH, VAULT_STORAGE_GROUP_ID } from '../../src/vault/storage-root.ts'
import { mlsEpoch } from '../../src/protocol/ids.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'
import type { SegmentKeyWrapV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const deviceA = await mlsDeviceFixture(identityId)
const deviceB = await mlsDeviceFixture(identityId, deviceA.rootPrivateKey)
const deviceKid = deviceA.kid
const deviceBKid = deviceB.kid

function memorySelfGroupStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

function memoryWrapStore(): SegmentKeyWrapReader & SegmentKeyWrapWriter {
  const rows = new Map<string, SegmentKeyWrapV1>()
  const key = (identityId: string, segmentId: string, epoch: string) => `${identityId} ${segmentId} ${epoch}`
  return {
    async readSegmentKeyWrap(id, segmentId, epoch) { return rows.get(key(id, segmentId, epoch)) },
    async writeSegmentKeyWrap(wrap) { rows.set(key(wrap.identityId, wrap.segmentId, wrap.recipientEpoch), wrap) },
  }
}

function memorySegmentStore(): ActiveVaultSegmentStore & { all(): VaultSegmentRecord[] } {
  const rows: VaultSegmentRecord[] = []
  return {
    async currentSegment(identityId) { return rows.find(r => r.identityId === identityId && !r.sealed) },
    async sealAndActivateSegment(next) {
      for (const row of rows) if (row.identityId === next.identityId && !row.sealed) row.sealed = true
      rows.push({ ...next })
    },
    async allSegments(id) { return rows.filter(row => row.identityId === id).map(row => ({ ...row, segmentKey: row.segmentKey.slice() })) },
    async recordSegmentRewrapped(id, segmentId, epoch) {
      const row = rows.find(value => value.identityId === id && value.segmentId === segmentId)
      if (!row) throw new Error('missing segment')
      row.epoch = epoch
    },
    all() { return rows },
  }
}

async function setupGenesisSelfGroup() {
  const kp = await generateOwnKeyPackage(deviceA.credential, deviceA.signaturePrivateKey)
  const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
  const selfGroupStore = memorySelfGroupStore()
  await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)
  expect(memberKids(state, identityId)).toEqual([deviceKid])
  return { selfGroupStore, state }
}

describe('buildVaultCryptoBoundary', () => {
  test('a SegmentKeyWrap signed via the boundary round-trips through a real self-group VEK', async () => {
    const { selfGroupStore, state } = await setupGenesisSelfGroup()
    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)

    const { deriveVaultEpochKey } = await import('../../src/mls/vault-epoch.ts')
    const { exportSecret } = await import('../../src/mls/group.ts')
    const epoch = mlsEpoch(epochOf(state))
    const vek = await deriveVaultEpochKey({ selfGroupId: selfGroupIdHex(identityId), epoch, exportSecret: (label, ctx, len) => exportSecret(state, label, ctx, len) })

    const segmentKey = crypto.getRandomValues(new Uint8Array(32))
    const wrap = await createSegmentKeyWrap(vek, segmentKey, {
      identityId, selfGroupId: selfGroupIdHex(identityId), segmentId: 'segment-1',
      sourceEpoch: epoch, recipientEpoch: epoch, grantorDeviceId: deviceKid, grantedAt: new Date().toISOString(),
    }, boundary.signer)
    await wraps.writeSegmentKeyWrap(wrap)

    const resolved = await boundary.resolver.resolveSegmentKey(identityId, 'segment-1')
    expect(resolved).toEqual(segmentKey)
  })

  test('verify rejects a grantor no longer in the self group', async () => {
    const { selfGroupStore } = await setupGenesisSelfGroup()
    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const boundary = buildVaultCryptoBoundary(memoryWrapStore(), memorySegmentStore(), selfGroupStore, record)

    const strangerKid = `${identityId}#not-a-member`
    const strangerKey = ed25519.utils.randomSecretKey()
    const signature = ed25519.sign(new TextEncoder().encode('anything'), strangerKey)
    const ok = await boundary.signer.verify(strangerKid, new TextEncoder().encode('anything'), signature)
    expect(ok).toBe(false)
  })

  test('activeSegment() mints once, reuses within an epoch, and seals + mints fresh after a commit', async () => {
    const { selfGroupStore, state } = await setupGenesisSelfGroup()
    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const segments = memorySegmentStore()
    const boundary = buildVaultCryptoBoundary(memoryWrapStore(), segments, selfGroupStore, record)

    const first = await boundary.activeSegment()
    expect(first.keyWraps).toHaveLength(1)
    const second = await boundary.activeSegment()
    // Same epoch, same identity -- the SAME segment must come back, not a new one.
    expect(second.segmentId).toBe(first.segmentId)
    expect(second.segmentKey).toEqual(first.segmentKey)
    expect(segments.all()).toHaveLength(1)
    expect(segments.all()[0]!.sealed).toBe(false)

    // Advance the self group's epoch (a commit) and persist the new state --
    // the same way reflectPendingSelfGroupCommits/maintainSelfGroup would.
    const result = await rekey(state)
    confirmCommit(result)
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), result.state)

    const third = await boundary.activeSegment()
    expect(third.segmentId).not.toBe(first.segmentId)
    expect(third.segmentKey).not.toEqual(first.segmentKey)
    expect(segments.all()).toHaveLength(2)
    // The old segment is now sealed; only the new one is current.
    expect(segments.all().find(s => s.segmentId === first.segmentId)?.sealed).toBe(true)
    expect(segments.all().find(s => s.segmentId === third.segmentId)?.sealed).toBe(false)
  })

  test('repairs a segment that skipped more than one MLS epoch from its endpoint-local key', async () => {
    const { selfGroupStore, state } = await setupGenesisSelfGroup()
    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const segments = memorySegmentStore()
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, segments, selfGroupStore, record)
    const original = await boundary.activeSegment()

    let current = state
    for (let index = 0; index < 2; index += 1) {
      const advanced = await rekey(current)
      confirmCommit(advanced)
      current = advanced.state
    }
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), current)

    expect(await repairCurrentLocalSegmentKeyWraps(selfGroupStore, segments, wraps, record)).toBe(1)
    expect(await boundary.resolver.resolveSegmentKey(identityId, original.segmentId)).toEqual(original.segmentKey)
    expect(segments.all()[0]!.epoch).toBe(mlsEpoch(epochOf(current)))
  })

  // Found live, 2026-08-31: every fresh Vault's very first segment is
  // created straight onto the storage-root scheme (a stable, root-derived
  // KEK -- vault/active-segment.ts's stableActiveSegment path, taken
  // whenever record.masterSeed is set, which every real identity has).
  // That segment's selfGroupId is the shared VAULT_STORAGE_GROUP_ID
  // constant, never stored.selfGroupId (the per-identity self-group id) --
  // so without an explicit skip, this loop's own mismatch check threw
  // unconditionally, on every boot, for every identity.
  test('skips a segment already on the storage-root scheme instead of throwing', async () => {
    const { selfGroupStore } = await setupGenesisSelfGroup()
    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const segments = memorySegmentStore()
    const wraps = memoryWrapStore()
    await segments.sealAndActivateSegment({
      identityId, segmentId: 'storage-root-segment', segmentKey: new Uint8Array(32).fill(7),
      selfGroupId: VAULT_STORAGE_GROUP_ID, epoch: VAULT_STORAGE_EPOCH, sealed: false, createdAt: new Date().toISOString(),
    })
    expect(await repairCurrentLocalSegmentKeyWraps(selfGroupStore, segments, wraps, record)).toBe(0)
    expect(segments.all()[0]!.selfGroupId).toBe(VAULT_STORAGE_GROUP_ID) // untouched, not "repaired" onto the self-group scheme
  })

  test('a device removed from the self group cannot decrypt a SegmentKey minted after its removal', async () => {
    // Device A creates the group; device B external-joins it (both real MLS
    // operations, no DS involved -- device A applies B's commit directly).
    const kpA = await generateOwnKeyPackage(deviceA.credential, deviceA.signaturePrivateKey)
    let stateA = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kpA)
    const kpB = await generateOwnKeyPackage(deviceB.credential, deviceB.signaturePrivateKey)
    const joinResult = await joinGroupExternally(await groupInfoForExternalJoin(stateA), kpB)
    const stateB = joinResult.state
    stateA = (await processIncoming(stateA, joinResult.commit)).state
    expect(new Set(memberKids(stateA, identityId))).toEqual(new Set([deviceKid, deviceBKid]))

    const selfGroupStoreA = memorySelfGroupStore()
    await selfGroupStoreA.save(identityId, selfGroupIdHex(identityId), stateA)
    const recordA: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const segments = memorySegmentStore()
    const wraps = memoryWrapStore()
    const boundaryA = buildVaultCryptoBoundary(wraps, segments, selfGroupStoreA, recordA)

    // A segment minted while B is still a member -- B's state at this point
    // (post-join, pre-removal) could derive this epoch's VEK too, same as A.
    const beforeRemoval = await boundaryA.activeSegment()

    // Device A removes device B. Device B never receives or applies this
    // commit -- its own `stateB` is frozen at the pre-removal epoch, exactly
    // like a removed device that is simply never told anything again.
    const removeResult = await removeMembers(stateA, [deviceBKid])
    confirmCommit(removeResult)
    stateA = removeResult.state
    await selfGroupStoreA.save(identityId, selfGroupIdHex(identityId), stateA)
    expect(memberKids(stateA, identityId)).toEqual([deviceKid])

    // A new segment minted AFTER the removal, under the new (post-removal) epoch.
    const afterRemoval = await boundaryA.activeSegment()
    expect(afterRemoval.segmentId).not.toBe(beforeRemoval.segmentId)
    const wrap = afterRemoval.keyWraps[0]!

    // Device B tries to unwrap it using the ONLY VEK its still-pre-removal
    // state can produce -- its own (stale) epoch's exporter secret. MLS
    // forward secrecy means this is not the epoch the wrap was actually
    // encrypted under, so the AEAD tag must fail to verify.
    const { deriveVaultEpochKey } = await import('../../src/mls/vault-epoch.ts')
    const staleEpoch = mlsEpoch(epochOf(stateB))
    const staleVek = await deriveVaultEpochKey({
      selfGroupId: selfGroupIdHex(identityId), epoch: staleEpoch,
      exportSecret: (label, ctx, len) => exportSecret(stateB, label, ctx, len),
    })
    const verifierThatTrustsAnyone = { verify: async () => true }
    await expect(unwrapSegmentKey(staleVek, wrap, verifierThatTrustsAnyone)).rejects.toThrow()
  })
})
