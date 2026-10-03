// This device's writable segment and the resolver that reads any segment's
// key back -- its own or one a sibling delivered through Vault Sync.
import { describe, expect, test } from 'bun:test'
import { ActiveVaultSegmentManager } from '../../src/client/store/vault/active-segment.ts'
import { StoredSegmentKeyResolver } from '../../src/client/store/vault/segment-key-resolver.ts'
import type { ActiveVaultSegmentStore, VaultSegmentRecord } from '../../src/client/store/vault/store.ts'

const identityId = 'did:web:alice.example'

function memorySegmentStore(): ActiveVaultSegmentStore & { rows: VaultSegmentRecord[] } {
  const rows: VaultSegmentRecord[] = []
  return {
    rows,
    async currentSegment(id) { return rows.find(r => r.identityId === id && !r.sealed) },
    async readSegmentKey(id, segmentId) { return rows.find(r => r.identityId === id && r.segmentId === segmentId)?.segmentKey.slice() },
    async sealAndActivateSegment(next) {
      for (const row of rows) if (row.identityId === next.identityId && !row.sealed) row.sealed = true
      rows.push({ ...next })
    },
  }
}

describe('ActiveVaultSegmentManager', () => {
  test('mints one segment and keeps returning it', async () => {
    const segments = memorySegmentStore()
    const manager = new ActiveVaultSegmentManager({ identityId, segments })
    const first = await manager.activeSegment()
    expect(first.segmentKey).toHaveLength(32)
    expect((await manager.activeSegment()).segmentId).toBe(first.segmentId)
    expect(segments.rows).toHaveLength(1)
  })
})

describe('StoredSegmentKeyResolver', () => {
  test('reads a held key and says so when Vault Sync has not delivered one yet', async () => {
    const segments = memorySegmentStore()
    const { segmentId, segmentKey } = await new ActiveVaultSegmentManager({ identityId, segments }).activeSegment()
    const resolver = new StoredSegmentKeyResolver(segments)
    expect(await resolver.resolveSegmentKey(identityId, segmentId)).toEqual(segmentKey)
    await expect(resolver.resolveSegmentKey(identityId, 'not-delivered')).rejects.toThrow('Vault Sync')
  })
})
