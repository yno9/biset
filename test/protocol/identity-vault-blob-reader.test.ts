// End-to-end: buildVaultBlobReader against a real MLS self group -- confirms
// PLAN.md §5.2's "stored key wrap からの SegmentKey resolver / attachment
// chunk reader" actually decrypts a vault object through a real self-group
// VEK, not a hand-built key, and serves range reads on the PLAINTEXT.
import { describe, expect, test } from 'bun:test'
import { buildVaultBlobReader, buildVaultCryptoBoundary } from '../../src/identity/bootstrap.ts'
import { createMlsGroup, generateOwnKeyPackage } from '../../src/mls/group.ts'
import { selfGroupIdHex } from '../../src/mls/self-group.ts'
import { encryptVaultObject } from '../../src/vault/objects.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultObjectRecord, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'
import type { SegmentKeyWrapV1 } from '../../src/protocol/vault.ts'

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

function memoryObjectStore(): { readObject(identityId: string, objectId: string): Promise<VaultObjectRecord | undefined>; put(record: VaultObjectRecord): void } {
  const rows = new Map<string, VaultObjectRecord>()
  return {
    async readObject(identityId, objectId) { return rows.get(`${identityId} ${objectId}`) },
    put(record) { rows.set(`${record.identityId} ${record.objectId}`, record) },
  }
}

describe('buildVaultBlobReader', () => {
  test('decrypts a vault object through a real self-group VEK and serves a range of the plaintext', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
    const segment = await boundary.activeSegment()

    const plaintext = new TextEncoder().encode('hello from device A, this is a raw RFC 5322 blob')
    const object = await encryptVaultObject(segment.segmentKey, { segmentId: segment.segmentId, plaintext, aad: new TextEncoder().encode('aad') })
    const objects = memoryObjectStore()
    objects.put({ ...object, identityId })

    const reader = buildVaultBlobReader(objects, wraps, selfGroupStore, identityId)

    const full = await reader.download(identityId, object.objectId)
    expect(full).toEqual(plaintext)

    const ranged = await reader.download(identityId, object.objectId, { start: 6, end: 9 })
    expect(new TextDecoder().decode(ranged)).toBe('from')
  })

  test('rejects an unknown blob ID', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const reader = buildVaultBlobReader(memoryObjectStore(), memoryWrapStore(), selfGroupStore, identityId)
    await expect(reader.download(identityId, 'no-such-object')).rejects.toThrow('vault blob not found')
  })

  test('rejects an out-of-range request', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const wraps = memoryWrapStore()
    const boundary = buildVaultCryptoBoundary(wraps, memorySegmentStore(), selfGroupStore, record)
    const segment = await boundary.activeSegment()

    const plaintext = new TextEncoder().encode('short')
    const object = await encryptVaultObject(segment.segmentKey, { segmentId: segment.segmentId, plaintext, aad: new TextEncoder().encode('aad') })
    const objects = memoryObjectStore()
    objects.put({ ...object, identityId })

    const reader = buildVaultBlobReader(objects, wraps, selfGroupStore, identityId)
    await expect(reader.download(identityId, object.objectId, { start: 0, end: 999 })).rejects.toThrow(RangeError)
  })
})
