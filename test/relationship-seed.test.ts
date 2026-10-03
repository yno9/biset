// The Vault relationship seed and its authority, read off the did:webvh log:
// who mints it (the first device; after a removal, the first remaining one),
// when it is stale (a device key was removed after it was minted), and that
// a removed device may not use one at all.
import { describe, expect, test } from 'bun:test'
import type { LogEntry } from '../src/protocol/webvh/log.ts'
import {
  createRelationshipSeedAuthority, DeviceRemovedError, isDesignatedSeedMinter, isFirstDidCommDevice, lastDeviceRemoval,
  RelationshipSeedPendingError,
} from '../src/client/didcomm/relationship-seed-bootstrap.ts'
import { mintRelationshipSeed, selectCurrentRelationshipSeed, type RelationshipSeedV1 } from '../src/client/store/vault/relationship-seed.ts'

const DID = 'did:webvh:scid:alice.example'
/** A log whose n-th entry (1-based) lists `keys[n-1]`. */
const log = (...keys: string[][]): LogEntry[] => keys.map((keyAgreement, index) => ({
  versionId: `${index + 1}-x`, versionTime: '', parameters: {}, state: { id: DID, keyAgreement },
} as unknown as LogEntry))
const kid = (fragment: string) => `${DID}#${fragment}`

describe('reading the log', () => {
  test('the first device is the key that entered the log alone', () => {
    const entries = log([], ['#k_phone'], ['#k_phone', '#k_laptop'], ['#k_laptop'])
    expect(isFirstDidCommDevice(entries, kid('k_phone'))).toBe(true)
    expect(isFirstDidCommDevice(entries, kid('k_laptop'))).toBe(false)
    expect(isFirstDidCommDevice(entries, kid('k_unknown'))).toBe(false)
  })

  test('keys compare by fragment, so a domain move (absolute ids under the old DID) changes nothing', () => {
    const entries = log([`did:webvh:scid:ex.alias#k_phone`], ['#k_phone', '#k_laptop'])
    expect(isFirstDidCommDevice(entries, kid('k_phone'))).toBe(true)
  })

  test('the latest entry that removed a key, and who survived it', () => {
    expect(lastDeviceRemoval(log(['#k_a'], ['#k_a', '#k_b']))).toBeUndefined()
    expect(lastDeviceRemoval(log(['#k_a'], ['#k_a', '#k_b'], ['#k_b'], ['#k_b', '#k_c']))).toEqual({ version: 3, survivors: ['#k_b'] })
  })

  test('after a removal, the designated minter is the first-sorting survivor still listed; before one, the first device', () => {
    const entries = log(['#k_a'], ['#k_a', '#k_c', '#k_b'], ['#k_c', '#k_b'], ['#k_c', '#k_b', '#k_0'])
    expect(isDesignatedSeedMinter(entries, kid('k_b'))).toBe(true)
    expect(isDesignatedSeedMinter(entries, kid('k_c'))).toBe(false)
    // Added after the removal: not a survivor of it, so not designated.
    expect(isDesignatedSeedMinter(entries, kid('k_0'))).toBe(false)
    expect(isDesignatedSeedMinter(log(['#k_a'], ['#k_a', '#k_b']), kid('k_a'))).toBe(true)
  })
})

describe('the seed authority', () => {
  function authority(entries: LogEntry[], ownKid: string, stored: RelationshipSeedV1[] = []) {
    const minted: RelationshipSeedV1[] = []
    const value = createRelationshipSeedAuthority({
      ownKid,
      seeds: { async current() { return selectCurrentRelationshipSeed([...stored, ...minted]) } },
      readLog: async () => entries,
      mintAndStore: async (afterVersion, supersedes) => {
        const seed = mintRelationshipSeed(DID, afterVersion, supersedes as RelationshipSeedV1 | undefined)
        minted.push(seed)
        return seed
      },
    })
    return { value, minted }
  }

  test('the first device mints the identity\'s first seed; any other device waits for it', async () => {
    const entries = log(['#k_phone'], ['#k_phone', '#k_laptop'])
    const phone = authority(entries, kid('k_phone'))
    expect((await phone.value.require()).seedId).toBe(phone.minted[0]!.seedId)
    expect(phone.minted[0]!.afterVersion).toBe(2)
    await expect(authority(entries, kid('k_laptop')).value.require()).rejects.toBeInstanceOf(RelationshipSeedPendingError)
  })

  test('a seed minted before a device was removed is stale: the designated survivor mints its successor, every other one waits', async () => {
    const old = mintRelationshipSeed(DID, 2)
    const entries = log(['#k_a'], ['#k_a', '#k_b', '#k_c'], ['#k_a', '#k_b'])
    const a = authority(entries, kid('k_a'), [old])
    const fresh = await a.value.require()
    expect(fresh.seedId).not.toBe(old.seedId)
    expect(a.minted[0]).toMatchObject({ afterVersion: 3, supersedesSeedId: old.seedId })
    await expect(authority(entries, kid('k_b'), [old]).value.require()).rejects.toBeInstanceOf(RelationshipSeedPendingError)
    // Once the successor reaches it (Vault Sync), the other one uses it.
    expect((await authority(entries, kid('k_b'), [old, a.minted[0]!]).value.require()).seedId).toBe(fresh.seedId)
  })

  test('a device no longer in the DID document may not use any seed', async () => {
    const seed = mintRelationshipSeed(DID, 1)
    const entries = log(['#k_a', '#k_b'], ['#k_a'])
    await expect(authority(entries, kid('k_b'), [seed]).value.require()).rejects.toBeInstanceOf(DeviceRemovedError)
  })

  test('concurrent callers share one mint', async () => {
    const a = authority(log(['#k_a']), kid('k_a'))
    const [first, second] = await Promise.all([a.value.require(), a.value.require()])
    expect(first.seedId).toBe(second.seedId)
    expect(a.minted).toHaveLength(1)
  })
})

describe('selectCurrentRelationshipSeed', () => {
  test('a superseded seed is never current; of the rest, the one minted at the latest log version', () => {
    const first = mintRelationshipSeed(DID, 1, undefined, new Date('2026-10-02T00:00:00Z'))
    const second = mintRelationshipSeed(DID, 5, first, new Date('2026-10-01T00:00:00Z'))
    expect(selectCurrentRelationshipSeed([first, second])?.seedId).toBe(second.seedId)
  })

  test('two rival heads at the same version resolve the same way on every device', () => {
    const base = mintRelationshipSeed(DID, 1, undefined, new Date('2026-10-01T00:00:00Z'))
    const a = mintRelationshipSeed(DID, 3, base, new Date('2026-10-02T00:00:00Z'))
    const b = mintRelationshipSeed(DID, 3, base, new Date('2026-10-02T00:00:00Z'))
    const expected = [a, b].sort((x, y) => x.seedId < y.seedId ? -1 : 1)[0]!.seedId
    expect(selectCurrentRelationshipSeed([a, b, base])?.seedId).toBe(expected)
  })
})
