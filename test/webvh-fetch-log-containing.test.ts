import { describe, expect, test } from 'bun:test'
import { fetchLogContaining, freshFetch } from '../src/client/identity/webvh/log-io.ts'

// A did:webvh log is JSON Lines; fetchCurrentLog only needs versionId and parameters of each entry.
const did = 'did:webvh:QmUKjahfVxnJHfj9iiWurMh6XF4umMdNvnqASv1LdAsNme:alice.did.md'
const entry = (n: number) => JSON.stringify({ versionId: `${n}-Qm${n}`, versionTime: `2026-10-02T00:00:0${n}Z`, parameters: n === 1 ? { updateKeys: ['z6MkA'], method: 'did:webvh:1.0', scid: 'QmScid' } : { updateKeys: [`z6Mk${n}`] }, state: { id: did }, proof: [] })
const logOf = (n: number) => Array.from({ length: n }, (_, i) => entry(i + 1)).join('\n') + '\n'

describe('freshFetch', () => {
  test('gives every request its own cache key and forbids the browser cache', async () => {
    const seen: Array<{ url: string; cache?: string }> = []
    const fetchImpl = (async (input: string, init?: RequestInit) => { seen.push({ url: input, cache: init?.cache }); return new Response('') }) as unknown as typeof fetch
    await freshFetch(fetchImpl)('https://alice.did.md/.well-known/did.jsonl')
    await freshFetch(fetchImpl)('https://alice.did.md/.well-known/did.jsonl')
    expect(seen[0]!.url).toStartWith('https://alice.did.md/.well-known/did.jsonl?_=')
    expect(seen[0]!.url).not.toBe(seen[1]!.url)
    expect(seen.every(request => request.cache === 'no-store')).toBe(true)
  })
})

describe('fetchLogContaining', () => {
  const serving = (...bodies: string[]) => { let calls = 0; const impl = (async () => new Response(bodies[Math.min(calls++, bodies.length - 1)])) as unknown as typeof fetch; return { impl, calls: () => calls } }

  test('returns at once when the log already contains the generation', async () => {
    const { impl, calls } = serving(logOf(3))
    expect((await fetchLogContaining(did, '3-Qm3', impl, [0])).entries).toHaveLength(3)
    expect(calls()).toBe(1)
  })
  test('a log that lags the write (a CDN copy) is read again until the generation appears', async () => {
    const { impl, calls } = serving(logOf(2), logOf(2), logOf(3))
    const log = await fetchLogContaining(did, '3-Qm3', impl, [0, 0, 0])
    expect(log.entries).toHaveLength(3)
    expect(log.last.parameters.updateKeys).toEqual(['z6Mk3'])
    expect(calls()).toBe(3)
  })
  test('a log that has moved on past the generation still contains it', async () => {
    const { impl } = serving(logOf(5))
    expect((await fetchLogContaining(did, '3-Qm3', impl, [0])).entries).toHaveLength(5)
  })
  test('gives up with a clear error instead of returning a log that predates the generation', async () => {
    const { impl, calls } = serving(logOf(2))
    await expect(fetchLogContaining(did, '3-Qm3', impl, [0, 0])).rejects.toThrow('does not contain 3-Qm3 yet')
    expect(calls()).toBe(3)
  })
})

import { updateKeysAtVersion } from '../src/protocol/webvh/log.ts'
import { parseLog } from '../src/protocol/webvh/log.ts'

describe('updateKeysAtVersion (with pre-rotation every entry names new update keys)', () => {
  const entries = parseLog(logOf(4))
  test('is the key set in force right after that entry, not the current one', () => {
    expect(updateKeysAtVersion(entries, '1-Qm1')).toEqual(['z6MkA'])
    expect(updateKeysAtVersion(entries, '2-Qm2')).toEqual(['z6Mk2'])
    expect(updateKeysAtVersion(entries, '4-Qm4')).toEqual(['z6Mk4'])
  })
  test('is undefined for an entry the log does not have', () => {
    expect(updateKeysAtVersion(entries, '9-Qm9')).toBeUndefined()
  })
})
