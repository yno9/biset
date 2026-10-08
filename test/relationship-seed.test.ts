// The relationship seed and its authority, read off the did:webvh log
// (PLAN-refactor.md §4.2, §7-1, §7-2, §9.2): the seed in use is the one whose
// rotation key the DID document publishes; a removed device may not use any.
import { describe, expect, test } from 'bun:test'
import type { LogEntry } from '../src/protocol/webvh/log.ts'
import {
  createRelationshipSeedAuthority, DeviceRemovedError, RelationshipSeedPendingError, SEED_LOST_AFTER_MS, seedStatus,
} from '../src/client/didcomm/relationship-seed-bootstrap.ts'
import { relationshipSeedRecord } from '../src/client/store/vault/relationship-seed.ts'
import { publishedRotationKey, rotationKeyEditMethod, rotationSigningKey, ROTATION_KEY_FRAGMENT } from '../src/client/didcomm/rotation-key.ts'

const DID = 'did:webvh:scid:alice.example'
const kid = (fragment: string) => `${DID}#${fragment}`
const T0 = Date.parse('2026-10-08T00:00:00Z')
const at = (ms: number) => new Date(T0 + ms).toISOString()

/** One log entry: the device keys it lists, and the rotation key it publishes (if any). */
interface Step { keys: string[]; rotation?: Uint8Array; time?: number }
const log = (...steps: Step[]): LogEntry[] => steps.map((step, index) => ({
  versionId: `${index + 1}-x`, versionTime: at(step.time ?? index * 1000), parameters: {},
  state: {
    id: DID,
    keyAgreement: step.keys.map(key => `#${key}`),
    authentication: ['#pass-1', ...(step.rotation ? [ROTATION_KEY_FRAGMENT] : [])],
    verificationMethod: step.rotation ? [{ id: ROTATION_KEY_FRAGMENT, type: 'Multikey', publicKeyMultibase: rotationSigningKey(step.rotation).publicKeyMultibase }] : [],
  },
} as unknown as LogEntry))
const seed = () => crypto.getRandomValues(new Uint8Array(32))
const stored = (value: Uint8Array) => relationshipSeedRecord(DID, value, 1)

describe('the rotation key', () => {
  test('is derived from the seed, the same on every device, and differs from seed to seed', () => {
    const value = seed()
    expect(rotationSigningKey(value).publicKeyMultibase).toBe(rotationSigningKey(value.slice()).publicKeyMultibase)
    expect(rotationSigningKey(seed()).publicKeyMultibase).not.toBe(rotationSigningKey(value).publicKeyMultibase)
  })

  test('is published only under its id and referenced from authentication', () => {
    const value = seed()
    const key = rotationSigningKey(value).publicKeyMultibase
    const method = { id: ROTATION_KEY_FRAGMENT, publicKeyMultibase: key }
    expect(publishedRotationKey({ id: DID, verificationMethod: [method], authentication: [ROTATION_KEY_FRAGMENT] })).toBe(key)
    expect(publishedRotationKey({ id: DID, verificationMethod: [{ ...method, id: kid('didcomm-rotation') }], authentication: [kid('didcomm-rotation')] })).toBe(key)
    expect(publishedRotationKey({ id: DID, verificationMethod: [method], authentication: [] })).toBeUndefined()
    expect(publishedRotationKey({ id: DID, verificationMethod: [], authentication: [ROTATION_KEY_FRAGMENT] })).toBeUndefined()
  })

  test('the edit entry asks for authentication, ifAbsent or replace', () => {
    const value = seed()
    expect(rotationKeyEditMethod(value, 'ifAbsent')).toMatchObject({ id: ROTATION_KEY_FRAGMENT, relationships: ['authentication'], mode: 'ifAbsent', publicKeyMultibase: rotationSigningKey(value).publicKeyMultibase })
    expect(rotationKeyEditMethod(value, 'replace').mode).toBe('replace')
  })
})

describe('seedStatus', () => {
  test('no rotation key published: unpublished', () => {
    expect(seedStatus(log({ keys: ['a'] }), kid('a'), [], T0).state).toBe('unpublished')
  })

  test('the seed whose key the document publishes is the one in use; another stored one is not', () => {
    const current = seed(), other = seed()
    const status = seedStatus(log({ keys: ['a', 'b'], rotation: current }), kid('b'), [stored(other), stored(current)], T0)
    expect(status.state).toBe('usable')
    expect(status.state === 'usable' && [...status.seed]).toEqual([...current])
  })

  test('without it, every device waits -- the designated one decides it is lost once no one else could have it, or after a day', () => {
    const current = seed()
    const entries = log({ keys: ['a', 'b'], rotation: current, time: 0 })
    expect(seedStatus(entries, kid('b'), [], T0 + SEED_LOST_AFTER_MS * 2).state).toBe('pending') // not designated ('a' sorts first)
    expect(seedStatus(entries, kid('a'), [], T0 + 1000).state).toBe('pending')
    expect(seedStatus(entries, kid('a'), [], T0 + SEED_LOST_AFTER_MS).state).toBe('lost')
    expect(seedStatus(log({ keys: ['a'], rotation: current }), kid('a'), [], T0).state).toBe('lost')
  })

  test('a device key removed after the rotation key was published (from the Wallet itself) makes it stale, even with the seed at hand', () => {
    const current = seed()
    const status = seedStatus(log({ keys: ['a', 'b', 'c'], rotation: current }, { keys: ['a', 'b'], rotation: current }), kid('b'), [stored(current)], T0)
    expect(status).toEqual({ state: 'stale', designated: false })
    expect(seedStatus(log({ keys: ['a', 'b', 'c'], rotation: current }, { keys: ['a', 'b'], rotation: current }), kid('a'), [], T0)).toEqual({ state: 'stale', designated: true })
  })

  test('removing devices in the same edit that replaces the key is not stale', () => {
    const old = seed(), fresh = seed()
    const entries = log({ keys: ['a', 'b', 'c'], rotation: old }, { keys: ['a'], rotation: fresh })
    expect(seedStatus(entries, kid('a'), [stored(old), stored(fresh)], T0).state).toBe('usable')
    // ... and a key added later does not either.
    expect(seedStatus([...entries, ...log({ keys: ['a'] }, { keys: ['a', 'd'], rotation: fresh }).slice(1)], kid('a'), [stored(fresh)], T0).state).toBe('usable')
  })

  test('a device no longer in the DID document may not use any seed', () => {
    const current = seed()
    expect(() => seedStatus(log({ keys: ['a', 'b'], rotation: current }, { keys: ['a'], rotation: current }), kid('b'), [stored(current)], T0)).toThrow(DeviceRemovedError)
  })
})

describe('the seed authority', () => {
  test('require() hands out the usable seed and refuses otherwise, saying why', async () => {
    const current = seed()
    let seeds = [stored(current)]
    const authority = createRelationshipSeedAuthority({ ownKid: kid('a'), seeds: { async readAll() { return seeds } }, async readLog() { return log({ keys: ['a', 'b'], rotation: current }) }, now: () => T0 })
    expect([...(await authority.require()).seed]).toEqual([...current])
    seeds = []
    const error = await authority.require().catch(value => value)
    expect(error).toBeInstanceOf(RelationshipSeedPendingError)
    expect((error as RelationshipSeedPendingError).status).toBe('pending')
  })

  test('the log is read once per period, and refresh() reads it again', async () => {
    let reads = 0
    const authority = createRelationshipSeedAuthority({ ownKid: kid('a'), seeds: { async readAll() { return [] } }, async readLog() { reads++; return log({ keys: ['a'] }) }, now: () => T0 })
    await authority.status(); await authority.status()
    expect(reads).toBe(1)
    authority.refresh(); await authority.status()
    expect(reads).toBe(2)
  })
})
