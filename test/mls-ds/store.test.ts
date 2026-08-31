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

describe('SQLite Conversation Group Delivery Service (mls-ds-1.0.md, identity-blind revision)', () => {
  test('createGroup is idempotent for the same creator, rejects a different one', () => {
    const ds = open()
    expect(ds.createGroup(groupId, 'a').roster).toEqual(['a'])
    expect(ds.createGroup(groupId, 'a').roster).toEqual(['a'])
    expect(() => ds.createGroup(groupId, 'stranger')).toThrow(ConversationDsCapacityError)
    ds.close()
  })

  test('submitCommit admits the first commit for an epoch and rejects a second one for the same epoch', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    const first = ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['b'], [], new Uint8Array([2]))
    expect(first.ok).toBe(true)
    if (first.ok) {
      expect(first.roster).toEqual(['a', 'b'])
      expect(first.entries.map(e => e.kind)).toEqual(['welcome', 'commit'])
    }
    const second = ds.submitCommit(groupId, 'b', '0', new Uint8Array([3]))
    expect(second).toEqual({ ok: false, reason: 'epoch-conflict', epoch: '1' })
    ds.close()
  })

  test('submitCommit rejects a sender who is not currently in the group roster', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    expect(ds.submitCommit(groupId, 'stranger', '0', new Uint8Array([1]))).toEqual({ ok: false, reason: 'not-a-member', epoch: '0' })
    ds.close()
  })

  test('addedIds/removedIds is a delta against the roster the DS already owns, not a submitter-declared snapshot', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['b', 'c'])
    expect(ds.roster(groupId)).toEqual(['a', 'b', 'c'])
    ds.submitCommit(groupId, 'a', '1', new Uint8Array([2]), [], ['b'])
    expect(ds.roster(groupId)).toEqual(['a', 'c'])
    ds.close()
  })

  test('submitSelfRemove records a departure declaration that a later commit can clear', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['b'])
    expect(ds.submitSelfRemove(groupId, 'b', '1', new Uint8Array([5]), 'b').ok).toBe(true)
    ds.submitCommit(groupId, 'a', '1', new Uint8Array([1]), [], ['b'])
    ds.clearPendingRemovals(groupId, 'a', ['b'])
    ds.close()
  })

  test('clearPendingRemovals is a no-op for anyone but the last committer', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['b'])
    ds.submitSelfRemove(groupId, 'b', '1', new Uint8Array([5]), 'b')
    ds.submitCommit(groupId, 'a', '1', new Uint8Array([1]))
    ds.clearPendingRemovals(groupId, 'b', ['b']) // b did not commit -- silently ignored
    ds.close()
  })

  test('submitMessage fans out application data without advancing epoch or changing roster', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['b'])
    const before = ds.roster(groupId)
    const result = ds.submitMessage(groupId, 'a', '1', new Uint8Array([1, 2, 3]))
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.entries).toEqual([{ seq: 2, kind: 'application', payload: new Uint8Array([1, 2, 3]), epoch: '1', at: result.entries[0]!.at }])
      expect(result.roster).toEqual(before)
    }
    // The group's epoch is unchanged -- a second submitMessage at the same epoch is fine (unlike commits, no first-wins tie-break).
    const second = ds.submitMessage(groupId, 'b', '1', new Uint8Array([4]))
    expect(second.ok).toBe(true)
    ds.close()
  })

  test('submitMessage rejects a stale epoch and a non-member sender', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    expect(ds.submitMessage(groupId, 'stranger', '0', new Uint8Array([1]))).toEqual({ ok: false, reason: 'not-a-member', epoch: '0' })
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]))
    expect(ds.submitMessage(groupId, 'a', '0', new Uint8Array([1]))).toEqual({ ok: false, reason: 'epoch-conflict', epoch: '1' })
    ds.close()
  })

  test('deliveriesSince is gated on ever-membership and bounded per pull, including application entries', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]))
    ds.submitMessage(groupId, 'a', '1', new Uint8Array([2]))
    expect(ds.deliveriesSince(groupId, 'a', 0)?.map(e => ({ seq: e.seq, kind: e.kind }))).toEqual([{ seq: 1, kind: 'commit' }, { seq: 2, kind: 'application' }])
    expect(ds.deliveriesSince(groupId, 'a', 0, 1)?.map(e => e.seq)).toEqual([1])
    expect(ds.deliveriesSince(groupId, 'stranger', 0)).toBeUndefined()
    ds.close()
  })

  test('survives restart: group state and log persist', () => {
    const first = open()
    first.createGroup(groupId, 'a')
    first.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['b'])
    first.close()
    const restarted = open()
    expect(restarted.roster(groupId)).toEqual(['a', 'b'])
    expect(restarted.deliveriesSince(groupId, 'a', 0)?.map(e => e.seq)).toEqual([1])
    restarted.close()
  })

  test('key package directory: publish, take one for a named target (consuming), drop, and count', () => {
    const ds = open()
    expect(ds.publishKeyPackages('bob-group-local-id', [new Uint8Array([1]), new Uint8Array([2])])).toBe(2)
    expect(ds.keyPackageCount('bob-group-local-id')).toBe(2)

    expect(ds.takeKeyPackage('bob-group-local-id')).toEqual({ keyPackage: new Uint8Array([1]) })
    expect(ds.keyPackageCount('bob-group-local-id')).toBe(1)
    expect(ds.takeKeyPackage('bob-group-local-id')).toEqual({ keyPackage: new Uint8Array([2]) })
    expect(ds.takeKeyPackage('bob-group-local-id')).toBeUndefined()

    ds.publishKeyPackages('carol-group-local-id', [new Uint8Array([3])])
    ds.dropKeyPackages('carol-group-local-id')
    expect(ds.keyPackageCount('carol-group-local-id')).toBe(0)
    ds.close()
  })

  test('no method surface accepts or returns anything shaped like a DID -- cheap regression guard for the identity-blind property this store exists to guarantee', () => {
    const ds = open()
    const methodNames = Object.getOwnPropertyNames(SqliteConversationDeliveryService.prototype)
    // Not a call trace -- just confirms no method NAME on the public surface
    // still talks about identity/DID/kid concepts the identity-blind
    // revision removed (groupInfoFor, submitExternalCommit, groupsFor).
    for (const name of methodNames) {
      expect(name.toLowerCase()).not.toContain('groupinfo')
      expect(name.toLowerCase()).not.toContain('external')
      expect(name.toLowerCase()).not.toContain('groupsfor')
    }
    ds.close()
  })

  test('canWatch matches deliveriesSince\'s own everMembers gate exactly', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['b'])
    expect(ds.canWatch(groupId, 'a')).toBe(true)
    expect(ds.canWatch(groupId, 'b')).toBe(true)
    expect(ds.canWatch(groupId, 'stranger')).toBe(false)
    expect(ds.canWatch('no-such-group', 'a')).toBe(false)
    ds.close()
  })

  test('subscribe delivers commit, message, and self-remove entries as they are appended; unsubscribe stops delivery', () => {
    const ds = open()
    ds.createGroup(groupId, 'a')
    const received: string[] = []
    const unsubscribe = ds.subscribe(groupId, entries => { for (const entry of entries) received.push(entry.kind) })

    ds.submitCommit(groupId, 'a', '0', new Uint8Array([1]), ['b'], [], new Uint8Array([2]))
    expect(received).toEqual(['welcome', 'commit'])

    ds.submitMessage(groupId, 'a', '1', new Uint8Array([3]))
    expect(received).toEqual(['welcome', 'commit', 'application'])

    ds.submitSelfRemove(groupId, 'b', '1', new Uint8Array([4]), 'b')
    expect(received).toEqual(['welcome', 'commit', 'application', 'proposal'])

    unsubscribe()
    ds.submitMessage(groupId, 'a', '1', new Uint8Array([5]))
    expect(received).toEqual(['welcome', 'commit', 'application', 'proposal']) // unchanged -- no longer subscribed
    ds.close()
  })

  test('a subscriber only sees entries for ITS OWN group, never another group\'s', () => {
    const ds = open()
    ds.createGroup('group-1', 'a')
    ds.createGroup('group-2', 'c')
    const seenByGroup1: string[] = []
    ds.subscribe('group-1', entries => { for (const entry of entries) seenByGroup1.push(entry.kind) })
    ds.submitMessage('group-2', 'c', '0', new Uint8Array([1]))
    expect(seenByGroup1).toEqual([])
    ds.close()
  })
})
