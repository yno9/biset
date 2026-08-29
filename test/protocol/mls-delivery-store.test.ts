import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { MlsDsCapacityError, SqliteMlsDeliveryService } from '../../src/coordinator/mls-delivery-store.ts'

const path = `/tmp/biset-mls-ds-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const groupId = 'group-1'

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function open(): SqliteMlsDeliveryService {
  return SqliteMlsDeliveryService.open(path)
}

describe('SQLite MLS Delivery Service (RFC 9750 §5)', () => {
  test('createGroup is idempotent for the same creator, rejects a different one', () => {
    const ds = open()
    expect(ds.createGroup(groupId, identityId, 'device-a', []).roster).toEqual(['device-a'])
    expect(ds.createGroup(groupId, identityId, 'device-a', []).roster).toEqual(['device-a'])
    expect(() => ds.createGroup(groupId, identityId, 'device-x', [])).toThrow(MlsDsCapacityError)
    ds.close()
  })

  test('submitCommit admits the first commit for an epoch and rejects a second one for the same epoch', () => {
    const ds = open()
    ds.createGroup(groupId, identityId, 'device-a', [])
    const first = ds.submitCommit(groupId, 'device-a', '0', new Uint8Array([1]), ['device-a', 'device-b'], new Uint8Array([2]), ['device-b'])
    expect(first.ok).toBe(true)
    if (first.ok) {
      expect(first.roster).toEqual(['device-a', 'device-b'])
      // Welcome numbered before the commit within the same accepted batch.
      expect(first.entries.map(e => e.kind)).toEqual(['welcome', 'commit'])
    }

    // device-b races a commit from the same (now stale) epoch and loses.
    const second = ds.submitCommit(groupId, 'device-b', '0', new Uint8Array([3]), ['device-a', 'device-b'])
    expect(second).toEqual({ ok: false, reason: 'epoch-conflict', epoch: '1' })
    ds.close()
  })

  test('submitCommit rejects a sender who is not currently in the group roster', () => {
    const ds = open()
    ds.createGroup(groupId, identityId, 'device-a', [])
    const result = ds.submitCommit(groupId, 'device-stranger', '0', new Uint8Array([1]), ['device-a'])
    expect(result).toEqual({ ok: false, reason: 'not-a-member', epoch: '0' })
    ds.close()
  })

  test('groupInfoFor is gated on the self-group\'s identity, not device membership', () => {
    const ds = open()
    ds.createGroup(groupId, identityId, 'device-a', [])
    ds.submitCommit(groupId, 'device-a', '0', new Uint8Array([1]), ['device-a'], undefined, undefined, new Uint8Array([9]))
    // A device that has never been a member can still fetch it: that is the
    // entire point of external join, which starts from exactly this call.
    expect(ds.groupInfoFor(groupId, identityId)).toEqual({ groupInfo: new Uint8Array([9]), pendingRemovals: [] })
    expect(ds.groupInfoFor(groupId, 'did:web:stranger.example')).toBeUndefined()
    ds.close()
  })

  test('a commit that omits a fresh GroupInfo drops the stored one', () => {
    const ds = open()
    ds.createGroup(groupId, identityId, 'device-a', [])
    ds.submitCommit(groupId, 'device-a', '0', new Uint8Array([1]), ['device-a'], undefined, undefined, new Uint8Array([9]))
    ds.submitCommit(groupId, 'device-a', '1', new Uint8Array([1]), ['device-a'])
    expect(ds.groupInfoFor(groupId, identityId)?.groupInfo).toBeUndefined()
    ds.close()
  })

  test('submitSelfRemove records a departure declaration that a later commit can clear', () => {
    const ds = open()
    ds.createGroup(groupId, identityId, 'device-a', ['device-b'])
    const proposed = ds.submitSelfRemove(groupId, 'device-b', '0', new Uint8Array([5]), 'device-b')
    expect(proposed.ok).toBe(true)
    expect(ds.groupInfoFor(groupId, identityId)?.pendingRemovals).toEqual(['device-b'])

    ds.submitCommit(groupId, 'device-a', '0', new Uint8Array([1]), ['device-a'])
    ds.clearPendingRemovals(groupId, 'device-a', ['device-b'])
    expect(ds.groupInfoFor(groupId, identityId)?.pendingRemovals).toEqual([])
    ds.close()
  })

  test('clearPendingRemovals is a no-op for anyone but the last committer', () => {
    const ds = open()
    ds.createGroup(groupId, identityId, 'device-a', ['device-b'])
    ds.submitSelfRemove(groupId, 'device-b', '0', new Uint8Array([5]), 'device-b')
    ds.submitCommit(groupId, 'device-a', '0', new Uint8Array([1]), ['device-a'])
    ds.clearPendingRemovals(groupId, 'device-b', ['device-b']) // device-b did not commit
    expect(ds.groupInfoFor(groupId, identityId)?.pendingRemovals).toEqual(['device-b'])
    ds.close()
  })

  test('submitExternalCommit requires a published GroupInfo, is gated on identity, and adds the joiner to the roster', () => {
    const ds = open()
    ds.createGroup(groupId, identityId, 'device-a', [])
    expect(ds.submitExternalCommit(groupId, identityId, 'device-b', '0', new Uint8Array([1]))).toEqual({ ok: false, reason: 'no-group-info', epoch: '0' })

    ds.submitCommit(groupId, 'device-a', '0', new Uint8Array([1]), ['device-a'], undefined, undefined, new Uint8Array([9]))
    // device-b has never been in the roster -- it is joining for the first time.
    const result = ds.submitExternalCommit(groupId, identityId, 'device-b', '1', new Uint8Array([2]), new Uint8Array([10]))
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.roster).toEqual(['device-a', 'device-b'])

    // A different identity cannot use this self-group's external-join path.
    expect(ds.submitExternalCommit(groupId, 'did:web:stranger.example', 'device-x', '2', new Uint8Array([3]))).toEqual({ ok: false, reason: 'not-a-member', epoch: '2' })
    ds.close()
  })

  test('deliveriesSince is gated on ever-membership and bounded per pull', () => {
    const ds = open()
    ds.createGroup(groupId, identityId, 'device-a', [])
    ds.submitCommit(groupId, 'device-a', '0', new Uint8Array([1]), ['device-a'])
    ds.submitCommit(groupId, 'device-a', '1', new Uint8Array([2]), ['device-a'])
    expect(ds.deliveriesSince(groupId, 'device-a', 0)?.map(e => e.seq)).toEqual([1, 2])
    expect(ds.deliveriesSince(groupId, 'device-a', 0, 1)?.map(e => e.seq)).toEqual([1])
    expect(ds.deliveriesSince(groupId, 'device-stranger', 0)).toBeUndefined()
    ds.close()
  })

  test('survives restart: group state and log persist', () => {
    const first = open()
    first.createGroup(groupId, identityId, 'device-a', [])
    first.submitCommit(groupId, 'device-a', '0', new Uint8Array([1]), ['device-a', 'device-b'])
    first.close()

    const restarted = open()
    expect(restarted.roster(groupId)).toEqual(['device-a', 'device-b'])
    expect(restarted.deliveriesSince(groupId, 'device-a', 0)?.map(e => e.seq)).toEqual([1])
    restarted.close()
  })

  test('key package directory: publish, take (consuming), drop, and count', async () => {
    const ds = open()
    expect(ds.publishKeyPackages('device-a', identityId, [new Uint8Array([1]), new Uint8Array([2])])).toBe(2)
    expect(ds.keyPackageCount('device-a')).toBe(2)

    const taken = await ds.takeKeyPackages(identityId, async () => true)
    expect(taken).toEqual([{ kid: 'device-a', keyPackage: new Uint8Array([1]) }])
    expect(ds.keyPackageCount('device-a')).toBe(1)

    ds.publishKeyPackages('device-b', identityId, [new Uint8Array([3])])
    // device-b is no longer live: takeKeyPackages drops its packages instead of handing them out.
    expect(await ds.takeKeyPackages(identityId, async kid => kid !== 'device-b')).toEqual([{ kid: 'device-a', keyPackage: new Uint8Array([2]) }])
    expect(ds.keyPackageCount('device-b')).toBe(0)

    ds.dropKeyPackages('device-a')
    expect(ds.keyPackageCount('device-a')).toBe(0)
    ds.close()
  })
})
