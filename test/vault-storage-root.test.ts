import { describe, expect, test } from 'bun:test'
import { ActiveVaultSegmentManager } from '../src/client/store/vault/active-segment.ts'
import { StoredSegmentKeyResolver, type VaultEpochKeyResolver } from '../src/client/store/vault/segment-key-resolver.ts'
import { deriveVaultStorageKek, VAULT_STORAGE_EPOCH, VAULT_STORAGE_GROUP_ID } from '../src/client/store/vault/storage-root.ts'
import type { SegmentKeyWrapV1 } from '../src/shared/protocol/vault.ts'
import type { VaultSegmentRecord } from '../src/client/store/vault/store.ts'

describe('stable Vault storage root', () => {
  test('is deterministic and independent of MLS state', async () => {
    const seed = new Uint8Array(32).fill(5)
    expect(deriveVaultStorageKek(seed)).toEqual(deriveVaultStorageKek(seed))
    expect(deriveVaultStorageKek(seed)).not.toEqual(deriveVaultStorageKek(new Uint8Array(32).fill(6)))

    let segment: VaultSegmentRecord | undefined
    const wraps = new Map<string, SegmentKeyWrapV1>()
    const segments = {
      async currentSegment() { return segment && copySegment(segment) },
      async allSegments() { return segment ? [copySegment(segment)] : [] },
      async sealAndActivateSegment(value: VaultSegmentRecord) { segment = copySegment(value) },
      async recordSegmentRewrapped(_identityId: string, _segmentId: string, epoch: string, selfGroupId?: string) { segment = { ...segment!, epoch, ...(selfGroupId ? { selfGroupId } : {}) } },
    }
    const wrapStore = {
      async readSegmentKeyWrap(_identityId: string, segmentId: string, epoch: string) { const value = wraps.get(`${segmentId}:${epoch}`); return value && copyWrap(value) },
      async writeSegmentKeyWrap(value: SegmentKeyWrapV1) { wraps.set(`${value.segmentId}:${value.recipientEpoch}`, copyWrap(value)) },
    }
    const noMls: VaultEpochKeyResolver = {
      async currentVaultEpoch() { throw new Error('MLS must not be read') },
      async deriveVaultEpochKey() { throw new Error('MLS must not derive storage keys') },
    }
    const storageKek = deriveVaultStorageKek(seed)
    const manager = new ActiveVaultSegmentManager({ identityId: 'did:example:alice', segments, wraps: wrapStore, epochs: noMls, storageKek, signer: { deviceId: 'device', async sign() { return new Uint8Array(64).fill(1) } } })
    const active = await manager.activeSegment()
    expect(segment).toMatchObject({ selfGroupId: VAULT_STORAGE_GROUP_ID, epoch: VAULT_STORAGE_EPOCH })
    const resolved = await new StoredSegmentKeyResolver(wrapStore, noMls, { verify: async () => { throw new Error('MLS signature must not gate storage') } }, storageKek).resolveSegmentKey('did:example:alice', active.segmentId)
    expect(resolved).toEqual(active.segmentKey)
  })
})

function copySegment(value: VaultSegmentRecord): VaultSegmentRecord { return { ...value, segmentKey: value.segmentKey.slice() } }
function copyWrap(value: SegmentKeyWrapV1): SegmentKeyWrapV1 { return { ...value, nonce: value.nonce.slice(), aad: value.aad.slice(), wrappedSegmentKey: value.wrappedSegmentKey.slice(), signature: value.signature.slice() } }
