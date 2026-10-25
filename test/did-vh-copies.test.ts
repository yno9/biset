// Comparing a log with the watchers' copies (protocol/vh/copies.ts), asked for by the caller (checkWatchers) and not otherwise.
import { afterEach, describe, expect, test } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { resolveDidDocument } from '../src/protocol/did-resolve.ts'
import { compareLogs, LogForkedError } from '../src/protocol/vh/copies.ts'
import { forgetCopyChecks } from '../src/protocol/vh/fetch.ts'
import { serializeLog, type LogEntry } from '../src/protocol/vh/log.ts'
import { buildGenesisLog, fixtureDomains } from './protocol/support/did-log-fixture.ts'
import { extendVhLog } from './protocol/support/vh-log-fixture.ts'

afterEach(() => forgetCopyChecks())

const priv = new Uint8Array(32).fill(11)
const pub = ed25519.getPublicKey(priv)
const WATCHER = 'https://watcher.test.example'
const { did, log: v1 } = buildGenesisLog(priv, pub, [], 'alice.test.example', { watchers: [WATCHER] })
const edit = (log: LogEntry[], name: string) => extendVhLog(log, priv, pub, state => { (state as { name?: string }).name = name }, '2026-08-24T00:00:00Z')
const v2 = edit(v1, 'two')
const v2fork = edit(v1, 'other two')

/** The host serves `host`'s log; each watcher serves its own (a missing key is a 404, `'down'` a 503, `'garbage'` not a log). */
function world(host: LogEntry[], watchers: Record<string, LogEntry[] | 'down' | 'garbage'> = {}, asked: string[] = []) {
  return (async (input: RequestInfo | URL) => {
    const url = new URL(String(input))
    asked.push(url.origin)
    if (url.hostname === fixtureDomains.get(did)) return new Response(serializeLog(host))
    const copy = watchers[url.origin]
    if (copy === 'down') return new Response('', { status: 503 })
    if (copy === 'garbage') return new Response('not a log')
    return copy ? new Response(serializeLog(copy)) : new Response('', { status: 404 })
  }) as typeof fetch
}
const resolve = (fetch: typeof fetch, extra: Record<string, unknown> = {}) => resolveDidDocument(did, { fetch, checkWatchers: true, ...extra })

describe('compareLogs', () => {
  test('same, ahead, behind, and forked at the first version that differs', () => {
    expect(compareLogs(v1, v1).status).toBe('same')
    expect(compareLogs(v1, v2).status).toBe('ahead')
    expect(compareLogs(v2, v1).status).toBe('behind')
    expect(compareLogs(v2, v2fork)).toEqual({ status: 'forked', forkedAt: 2 })
  })
})

describe('checkWatchers', () => {
  test('a watcher the owner lists holds a newer copy: it replaces the one the host served', async () => {
    const document = await resolve(world(v1, { [WATCHER]: v2 }))
    expect((document as { name?: string }).name).toBe('two')
  })

  test('a copy that is the same, older, missing, down or not a log changes nothing and stops nothing', async () => {
    for (const copy of [v1, 'down', 'garbage'] as const) {
      forgetCopyChecks()
      const document = await resolve(world(v2, { [WATCHER]: copy }))
      expect((document as { name?: string }).name).toBe('two')
    }
    forgetCopyChecks()
    expect(((await resolve(world(v2))) as { name?: string }).name).toBe('two') // 404
  })

  test('two continuations of one history are refused, not resolved to either', async () => {
    await expect(resolve(world(v2, { [WATCHER]: v2fork }))).rejects.toThrow(LogForkedError)
    forgetCopyChecks()
    await expect(resolve(world(v2fork, { [WATCHER]: v2 }))).rejects.toMatchObject({ copies: [{ source: WATCHER, status: 'forked', forkedAt: 2 }] })
  })

  test('the client\'s own watchers are asked too, and only https ones', async () => {
    const asked: string[] = []
    const extra = 'https://extra.test.example'
    const document = await resolve(world(v1, { [extra]: v2 }, asked), { vh: { watchers: [extra, 'http://plain.test.example'] } })
    expect((document as { name?: string }).name).toBe('two')
    expect(asked).not.toContain('http://plain.test.example')
  })

  test('not asked unless the caller asks: a plain resolution fetches the one copy', async () => {
    const asked: string[] = []
    const document = await resolveDidDocument(did, { fetch: world(v1, { [WATCHER]: v2 }, asked) })
    expect((document as { name?: string }).name).toBeUndefined()
    expect(asked.every(origin => origin.endsWith('alice.test.example'))).toBe(true)
  })

  test('a check is reused for a few minutes: the same log is not compared again', async () => {
    const asked: string[] = []
    const fetchImpl = world(v1, { [WATCHER]: v1 }, asked)
    await resolve(fetchImpl)
    const first = asked.filter(origin => origin === WATCHER).length
    await resolve(fetchImpl)
    expect(asked.filter(origin => origin === WATCHER).length).toBe(first)
  })
})
