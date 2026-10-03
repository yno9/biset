// The Vault relationship seed: who may mint it (the identity's first device,
// read off the did:webvh log), and how devices agree on one when two exist.
import { describe, expect, test } from 'bun:test'
import type { LogEntry } from '../src/protocol/webvh/log.ts'
import { finishDeviceRemoval, isFirstDidCommDevice, provisionRelationshipSeed, requireRelationshipSeed, RelationshipSeedPendingError } from '../src/client/didcomm/relationship-seed-bootstrap.ts'
import { mintRelationshipSeed, selectCurrentRelationshipSeed } from '../src/client/store/vault/relationship-seed.ts'

const DID = 'did:webvh:scid:alice.example'
const entry = (keyAgreement: string[]): LogEntry => ({ versionId: '1-x', versionTime: '', parameters: {}, state: { id: DID, keyAgreement } } as unknown as LogEntry)

describe('isFirstDidCommDevice', () => {
  test('the key that entered the log alone is first; one added beside another is not', () => {
    const log = [entry([]), entry(['#k_phone']), entry(['#k_phone', '#k_laptop']), entry(['#k_laptop'])]
    expect(isFirstDidCommDevice(DID, log, `${DID}#k_phone`)).toBe(true)
    expect(isFirstDidCommDevice(DID, log, `${DID}#k_laptop`)).toBe(false)
    expect(isFirstDidCommDevice(DID, log, `${DID}#k_unknown`)).toBe(false)
  })

  test('the answer depends on the entry that added the key, not on today\'s document', () => {
    // The phone was removed later; the laptop still was not first.
    const log = [entry(['#k_phone']), entry(['#k_phone', '#k_laptop']), entry(['#k_laptop'])]
    expect(isFirstDidCommDevice(DID, log, `${DID}#k_laptop`)).toBe(false)
  })
})

describe('provisionRelationshipSeed', () => {
  const run = (log: LogEntry[], ownKid: string, existing?: Uint8Array) => {
    let minted = 0
    return provisionRelationshipSeed({
      did: DID, ownKid,
      seeds: { current: async () => existing ? { seed: existing } : undefined },
      readLog: async () => log,
      mintAndStore: async () => { minted++ },
    }).then(outcome => ({ outcome, minted }))
  }
  test('present seed: nothing to do; first device: mints; any other device: waits', async () => {
    const log = [entry(['#k_phone']), entry(['#k_phone', '#k_laptop'])]
    expect(await run(log, `${DID}#k_phone`, new Uint8Array(32))).toEqual({ outcome: 'present', minted: 0 })
    expect(await run(log, `${DID}#k_phone`)).toEqual({ outcome: 'minted', minted: 1 })
    expect(await run(log, `${DID}#k_laptop`)).toEqual({ outcome: 'waiting', minted: 0 })
  })

  test('relationship work without a seed is deferred, not improvised', async () => {
    await expect(requireRelationshipSeed({ current: async () => undefined })).rejects.toBeInstanceOf(RelationshipSeedPendingError)
  })
})

describe('selectCurrentRelationshipSeed', () => {
  test('a superseded seed is never current', () => {
    const first = mintRelationshipSeed(DID, undefined, new Date('2026-10-01T00:00:00Z'))
    const second = mintRelationshipSeed(DID, first, new Date('2026-10-02T00:00:00Z'))
    expect(selectCurrentRelationshipSeed([second, first])?.seedId).toBe(second.seedId)
  })

  test('two rival heads resolve the same way on every device', () => {
    const base = mintRelationshipSeed(DID, undefined, new Date('2026-10-01T00:00:00Z'))
    const a = mintRelationshipSeed(DID, base, new Date('2026-10-02T00:00:00Z'))
    const b = mintRelationshipSeed(DID, base, new Date('2026-10-02T00:00:00Z'))
    const expected = [a, b].sort((x, y) => x.seedId < y.seedId ? -1 : 1)[0]!.seedId
    expect(selectCurrentRelationshipSeed([a, b, base])?.seedId).toBe(expected)
    expect(selectCurrentRelationshipSeed([b, base, a])?.seedId).toBe(expected)
  })
})

describe('finishDeviceRemoval', () => {
  test('mints a seed superseding the current one, once', async () => {
    const stored: ReturnType<typeof mintRelationshipSeed>[] = [mintRelationshipSeed(DID, undefined, new Date('2026-10-01T00:00:00Z'))]
    const input = {
      identityId: DID,
      requestedAt: '2026-10-02T00:00:00.000Z',
      seeds: { current: async () => selectCurrentRelationshipSeed(stored) },
      storeSeed: async (seed: ReturnType<typeof mintRelationshipSeed>) => { stored.push(seed) },
      mint: (identityId: string, supersedes?: ReturnType<typeof mintRelationshipSeed>) => mintRelationshipSeed(identityId, supersedes),
    }
    const next = await finishDeviceRemoval(input)
    expect(next.supersedesSeedId).toBe(stored[0]!.seedId)
    // A crash before the marker is cleared: the rerun finds the work done.
    expect((await finishDeviceRemoval(input)).seedId).toBe(next.seedId)
    expect(stored).toHaveLength(2)
  })
})
