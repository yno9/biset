import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ConversationDsCapacityError, SqliteConversationDeliveryService } from '../../src/mls-ds/store.ts'

const path = `/tmp/biset-conversation-ds-${process.pid}-${Date.now()}.sqlite`
const groupId = 'group-1'

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function open(): SqliteConversationDeliveryService {
  return SqliteConversationDeliveryService.open(path)
}

describe('SQLite Conversation Group Delivery Service (mls-ds-1.0.md)', () => {
  test('createGroup is idempotent for the same creator, rejects a different one', () => {
    const ds = open()
    expect(ds.createGroup(groupId, 'did:web:alice.example#key-1', []).roster).toEqual(['did:web:alice.example#key-1'])
    expect(ds.createGroup(groupId, 'did:web:alice.example#key-1', []).roster).toEqual(['did:web:alice.example#key-1'])
    expect(() => ds.createGroup(groupId, 'did:web:stranger.example#key-1', [])).toThrow(ConversationDsCapacityError)
    ds.close()
  })

  test('submitCommit admits the first commit for an epoch and rejects a second one for the same epoch', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', [])
    const first = ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a', 'b'], new Uint8Array([2]), ['b'])
    expect(first.ok).toBe(true)
    if (first.ok) {
      expect(first.roster).toEqual(['a', 'b'])
      expect(first.entries.map(e => e.kind)).toEqual(['welcome', 'commit'])
    }
    const second = ds.submitCommit(groupId, 'b', '0', new Uint8Array([3]), ['a', 'b'])
    expect(second).toEqual({ ok: false, reason: 'epoch-conflict', epoch: '1' })
    ds.close()
  })

  test('submitCommit rejects a sender who is not currently in the group roster', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', [])
    expect(ds.submitCommit(groupId, 'stranger', '0', new Uint8Array([1]), ['a'])).toEqual({ ok: false, reason: 'not-a-member', epoch: '0' })
    ds.close()
  })

  test('groupInfoFor is gated on nothing but the group existing -- unlike Self Group, no identity to check membership of', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', [])
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a'], undefined, undefined, new Uint8Array([9]))
    // Anyone who knows groupId can fetch it -- that IS the invitation, per
    // the store's own doc comment (PLAN_biset-mls-ds.md §11-2's bootstrap
    // protocol is what's meant to keep groupId non-guessable).
    expect(ds.groupInfoFor(groupId)).toEqual({ groupInfo: new Uint8Array([9]), pendingRemovals: [] })
    expect(ds.groupInfoFor('no-such-group')).toBeUndefined()
    ds.close()
  })

  test('a commit that omits a fresh GroupInfo drops the stored one', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', [])
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a'], undefined, undefined, new Uint8Array([9]))
    ds.submitCommit(groupId, 'a', '1', new Uint8Array([1]), ['a'])
    expect(ds.groupInfoFor(groupId)?.groupInfo).toBeUndefined()
    ds.close()
  })

  test('submitSelfRemove records a departure declaration that a later commit can clear', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', ['b'])
    expect(ds.submitSelfRemove(groupId, 'b', '0', new Uint8Array([5]), 'b').ok).toBe(true)
    expect(ds.groupInfoFor(groupId)?.pendingRemovals).toEqual(['b'])
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a'])
    ds.clearPendingRemovals(groupId, 'a', ['b'])
    expect(ds.groupInfoFor(groupId)?.pendingRemovals).toEqual([])
    ds.close()
  })

  test('clearPendingRemovals is a no-op for anyone but the last committer', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', ['b'])
    ds.submitSelfRemove(groupId, 'b', '0', new Uint8Array([5]), 'b')
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a'])
    ds.clearPendingRemovals(groupId, 'b', ['b']) // b did not commit
    expect(ds.groupInfoFor(groupId)?.pendingRemovals).toEqual(['b'])
    ds.close()
  })

  test('submitExternalCommit requires a published GroupInfo, has no identity gate, and adds the joiner to the roster', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', [])
    expect(ds.submitExternalCommit(groupId, 'b', '0', new Uint8Array([1]))).toEqual({ ok: false, reason: 'no-group-info', epoch: '0' })
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a'], undefined, undefined, new Uint8Array([9]))
    const result = ds.submitExternalCommit(groupId, 'b', '1', new Uint8Array([2]), new Uint8Array([10]))
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.roster).toEqual(['a', 'b'])
    ds.close()
  })

  test('submitMessage fans out application data without advancing epoch or changing roster', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', ['b'])
    const before = ds.roster(groupId)
    const result = ds.submitMessage(groupId, 'a', '0', new Uint8Array([1, 2, 3]))
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.entries).toEqual([{ seq: 1, kind: 'application', payload: new Uint8Array([1, 2, 3]), epoch: '0', at: result.entries[0]!.at }])
      expect(result.roster).toEqual(before)
    }
    // The group's epoch is unchanged -- a second submitMessage at the same epoch is fine (unlike commits, no first-wins tie-break).
    const second = ds.submitMessage(groupId, 'b', '0', new Uint8Array([4]))
    expect(second.ok).toBe(true)
    ds.close()
  })

  test('submitMessage rejects a stale epoch and a non-member sender', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', [])
    expect(ds.submitMessage(groupId, 'stranger', '0', new Uint8Array([1]))).toEqual({ ok: false, reason: 'not-a-member', epoch: '0' })
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a'])
    expect(ds.submitMessage(groupId, 'a', '0', new Uint8Array([1]))).toEqual({ ok: false, reason: 'epoch-conflict', epoch: '1' })
    ds.close()
  })

  test('deliveriesSince is gated on ever-membership and bounded per pull, including application entries', () => {
    const ds = open()
    ds.createGroup(groupId, 'a', [])
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a'])
    ds.submitMessage(groupId, 'a', '1', new Uint8Array([2]))
    expect(ds.deliveriesSince(groupId, 'a', 0)?.map(e => ({ seq: e.seq, kind: e.kind }))).toEqual([{ seq: 1, kind: 'commit' }, { seq: 2, kind: 'application' }])
    expect(ds.deliveriesSince(groupId, 'a', 0, 1)?.map(e => e.seq)).toEqual([1])
    expect(ds.deliveriesSince(groupId, 'stranger', 0)).toBeUndefined()
    ds.close()
  })

  test('survives restart: group state and log persist', () => {
    const first = open()
    first.createGroup(groupId, 'a', [])
    first.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['a', 'b'])
    first.close()
    const restarted = open()
    expect(restarted.roster(groupId)).toEqual(['a', 'b'])
    expect(restarted.deliveriesSince(groupId, 'a', 0)?.map(e => e.seq)).toEqual([1])
    restarted.close()
  })

  test('key package directory: publish, take one for a named target (consuming), drop, and count', () => {
    const ds = open()
    expect(ds.publishKeyPackages('bob-device', [new Uint8Array([1]), new Uint8Array([2])])).toBe(2)
    expect(ds.keyPackageCount('bob-device')).toBe(2)

    expect(ds.takeKeyPackage('bob-device')).toEqual({ keyPackage: new Uint8Array([1]) })
    expect(ds.keyPackageCount('bob-device')).toBe(1)
    expect(ds.takeKeyPackage('bob-device')).toEqual({ keyPackage: new Uint8Array([2]) })
    expect(ds.takeKeyPackage('bob-device')).toBeUndefined()

    ds.publishKeyPackages('carol-device', [new Uint8Array([3])])
    ds.dropKeyPackages('carol-device')
    expect(ds.keyPackageCount('carol-device')).toBe(0)
    ds.close()
  })

  test('groupsFor lists every group a kid has ever belonged to', () => {
    const ds = open()
    ds.createGroup('group-1', 'a', ['b'])
    ds.createGroup('group-2', 'c', [])
    expect(ds.groupsFor('b').map(g => g.groupId)).toEqual(['group-1'])
    expect(ds.groupsFor('a').map(g => g.groupId)).toEqual(['group-1'])
    expect(ds.groupsFor('c').map(g => g.groupId)).toEqual(['group-2'])
    ds.close()
  })
})
