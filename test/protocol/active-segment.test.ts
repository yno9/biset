// PLAN.md §4.1's "VEK を永続化しないことを code review / test で保証する" --
// ActiveVaultSegmentManager.mintWrap is the WRITE-side counterpart to
// StoredSegmentKeyResolver.resolveSegmentKey (segment-key-resolver.test.ts
// already covers the read side): every time it mints a fresh segment or
// backfills a missing wrap, it derives a VEK, uses it once, and must clear
// it before returning -- never hand a live VEK, or leave one lying around
// in memory, past the single AEAD wrap operation it exists for.
import { describe, expect, test } from 'bun:test'
import { ActiveVaultSegmentManager } from '../../src/vault/active-segment.ts'
import type { SegmentKeyWrapSigner } from '../../src/vault/crypto.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import type { VaultEpochKeyResolver } from '../../src/vault/segment-key-resolver.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from '../../src/vault/store.ts'
import type { SegmentKeyWrapV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const signer: SegmentKeyWrapSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify() { return true },
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

/** Captures every VEK this resolver ever derives, by reference (not a copy), so the test can inspect it AFTER the caller is done with it. */
function watchingEpochResolver(selfGroupId: string, epoch: string): { epochs: VaultEpochKeyResolver; derived: Uint8Array[] } {
  const derived: Uint8Array[] = []
  return {
    epochs: {
      async currentVaultEpoch() { return { selfGroupId, epoch } },
      async deriveVaultEpochKey() {
        const vek = createSegmentKey()
        derived.push(vek)
        return vek
      },
    },
    derived,
  }
}

describe('ActiveVaultSegmentManager VEK hygiene', () => {
  test('clears the VEK it derives to mint a fresh segment', async () => {
    const { epochs, derived } = watchingEpochResolver('self-group-a', '3')
    const manager = new ActiveVaultSegmentManager({ identityId, segments: memorySegmentStore(), wraps: memoryWrapStore(), epochs, signer })

    const segment = await manager.activeSegment()
    expect(segment.keyWraps).toHaveLength(1)
    expect(derived).toHaveLength(1)
    expect(derived[0]).toEqual(new Uint8Array(32))
  })

  test('clears the VEK it derives when backfilling a missing wrap for an existing segment', async () => {
    const { epochs, derived } = watchingEpochResolver('self-group-a', '3')
    const segments = memorySegmentStore()
    const wraps = memoryWrapStore()
    const manager = new ActiveVaultSegmentManager({ identityId, segments, wraps, epochs, signer })

    // Simulate a crash between sealAndActivateSegment and writeSegmentKeyWrap
    // on a prior call: the segment record exists, but its wrap does not.
    await segments.sealAndActivateSegment({
      identityId, segmentId: 'segment-orphan', segmentKey: createSegmentKey(),
      selfGroupId: 'self-group-a', epoch: '3', sealed: false, createdAt: '2026-08-24T00:00:00.000Z',
    })

    const segment = await manager.activeSegment()
    expect(segment.segmentId).toBe('segment-orphan')
    expect(segment.keyWraps).toHaveLength(1)
    expect(derived).toHaveLength(1)
    expect(derived[0]).toEqual(new Uint8Array(32))
  })

  test('clears each VEK across a mint-then-reseal sequence, never leaving a live one behind', async () => {
    let epoch = '3'
    const derived: Uint8Array[] = []
    const epochs: VaultEpochKeyResolver = {
      async currentVaultEpoch() { return { selfGroupId: 'self-group-a', epoch } },
      async deriveVaultEpochKey() {
        const vek = createSegmentKey()
        derived.push(vek)
        return vek
      },
    }
    const manager = new ActiveVaultSegmentManager({ identityId, segments: memorySegmentStore(), wraps: memoryWrapStore(), epochs, signer })

    const first = await manager.activeSegment()
    epoch = '4'
    const second = await manager.activeSegment()
    expect(second.segmentId).not.toBe(first.segmentId)

    expect(derived).toHaveLength(2)
    for (const vek of derived) expect(vek).toEqual(new Uint8Array(32))
  })
})
