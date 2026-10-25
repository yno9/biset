import { expect, test } from 'vitest'
import { ForkedLogError, InMemoryVersionMemory, StaleLogError, checkAndRemember, latestVersion, standingOf, versionNumberOf } from '../../src/protocol/freshness.ts'
import { resolveVhEntries } from '../../src/protocol/vh/resolver.ts'
import { identityKey } from '../../src/protocol/webvh/identifier.ts'
import type { LogEntry } from '../../src/protocol/webvh/log.ts'
import vectors from '../fixtures/did-vh-vectors.json'

const entries = (...ids: string[]) => ids.map(versionId => ({ versionId }))

test('versionNumberOf reads the number and refuses a malformed versionId', () => {
  expect(versionNumberOf('12-QmAbc')).toBe(12)
  for (const bad of ['', '0-Qm', 'x-Qm', '3', '-Qm']) expect(() => versionNumberOf(bad)).toThrow()
})

test('standingOf: nothing known is new; the same log is same; a longer one extending it is newer', () => {
  const three = entries('1-a', '2-b', '3-c')
  expect(standingOf(three)).toBe('new')
  expect(standingOf(three, latestVersion(three))).toBe('same')
  expect(standingOf(three, latestVersion(entries('1-a', '2-b')))).toBe('newer')
})

test('standingOf refuses an older copy (stale) and another continuation (forked), even a longer one', () => {
  const known = latestVersion(entries('1-a', '2-b', '3-c'))
  expect(() => standingOf(entries('1-a', '2-b'), known)).toThrow(StaleLogError)
  expect(() => standingOf(entries('1-a', '2-b', '3-x'), known)).toThrow(ForkedLogError)
  expect(() => standingOf(entries('1-a', '2-x', '3-y', '4-z'), known)).toThrow(ForkedLogError)
  expect(standingOf(entries('1-a', '2-b', '3-c', '4-d'), known)).toBe('newer')
})

test('checkAndRemember keeps the newest version and never moves back; identities are separate', async () => {
  const memory = new InMemoryVersionMemory()
  expect(await checkAndRemember(memory, 'k', entries('1-a', '2-b'))).toBe('new')
  expect(await checkAndRemember(memory, 'k', entries('1-a', '2-b', '3-c'))).toBe('newer')
  await expect(checkAndRemember(memory, 'k', entries('1-a'))).rejects.toThrow(StaleLogError)
  expect(memory.get('k')).toEqual({ versionNumber: 3, versionId: '3-c' })
  expect(await checkAndRemember(memory, 'k', entries('1-a', '2-b', '3-c'))).toBe('same')
  expect(await checkAndRemember(memory, 'other', entries('1-z'))).toBe('new')
})

test('with a verified did:vh log: a rotation rolled back by a host is refused', async () => {
  const file = vectors as unknown as { now: string; vectors: Array<{ name: string; did: string; log: unknown[] }> }
  const vector = file.vectors.find(v => v.name === 'valid/rotation-without-prerotation')!
  const full = vector.log as LogEntry[]
  const now = Date.parse(file.now)
  const key = identityKey(vector.did)
  expect(key).toBe(vector.did) // a did:vh is its own identity key
  const memory = new InMemoryVersionMemory()
  resolveVhEntries(vector.did, full, { now })
  await checkAndRemember(memory, key, full)
  const older = full.slice(0, 2)
  resolveVhEntries(vector.did, older, { now }) // verifies on its own...
  await expect(checkAndRemember(memory, key, older)).rejects.toThrow(StaleLogError) // ...but is older than what was accepted
})
