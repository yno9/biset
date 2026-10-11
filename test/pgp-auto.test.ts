import { expect, test } from 'bun:test'
import { ensureOwnPgpKey, publishedKeyState, wkdHash } from '../src/client/pgp/auto.ts'

const never = new Promise<never>(() => {})

test('wkdHash matches the bridge (z-base-32 of SHA-1)', async () => {
  expect(await wkdHash('702b')).toBe('x774szrw1ihsa5eagkqpp9ttpi4jnq7b')
  expect(await wkdHash('702B')).toBe('x774szrw1ihsa5eagkqpp9ttpi4jnq7b')
})

function run(options: { has?: boolean[]; wkd?: ('present' | 'absent' | 'unknown')[] }) {
  const has = [...(options.has ?? [false, false])]
  const wkd = [...(options.wkd ?? ['absent', 'absent'])]
  const calls = { generate: 0 }
  const outcome = ensureOwnPgpKey({
    address: 'alice@did.md',
    hasKey: async () => has.shift() ?? false,
    generate: async () => { calls.generate += 1 },
    vaultPulled: Promise.resolve(),
    settleMs: 0,
    wkd: async () => wkd.shift() ?? 'absent',
    sleep: async () => {},
  })
  return { outcome, calls }
}

test('no key in the Vault and none published: one is made', async () => {
  const { outcome, calls } = run({})
  expect(await outcome).toBe('generated')
  expect(calls.generate).toBe(1)
})

test('a key already in the Vault is left alone', async () => {
  const { outcome, calls } = run({ has: [true] })
  expect(await outcome).toBe('have-key')
  expect(calls.generate).toBe(0)
})

test('a key published elsewhere (a second device) is not replaced', async () => {
  const { outcome, calls } = run({ wkd: ['present'] })
  expect(await outcome).toBe('published-elsewhere')
  expect(calls.generate).toBe(0)
})

test('a directory that does not answer properly makes no key', async () => {
  const { outcome, calls } = run({ wkd: ['unknown'] })
  expect(await outcome).toBe('unsure')
  expect(calls.generate).toBe(0)
})

test('a sibling key that lands during the wait stops the generation', async () => {
  const { outcome, calls } = run({ has: [false, true] })
  expect(await outcome).toBe('have-key')
  expect(calls.generate).toBe(0)
})

test('a key published during the wait stops the generation', async () => {
  const { outcome, calls } = run({ wkd: ['absent', 'present'] })
  expect(await outcome).toBe('unsure')
  expect(calls.generate).toBe(0)
})

test('a failed Vault pull does not block, and does not stop the generation', async () => {
  const calls = { generate: 0 }
  const outcome = await ensureOwnPgpKey({
    address: 'alice@did.md', hasKey: async () => false, generate: async () => { calls.generate += 1 },
    vaultPulled: Promise.reject(new Error('offline')), settleMs: 0, wkd: async () => 'absent', sleep: async () => {},
  })
  expect(outcome).toBe('generated')
  expect(calls.generate).toBe(1)
})

test('publishedKeyState: 404 is absent, a binary 200 is present, a catch-all text 200 is unknown', async () => {
  const answer = (status: number, type: string, body: string) => (async () => new Response(body, { status, headers: { 'content-type': type } })) as unknown as typeof fetch
  expect(await publishedKeyState('alice@did.md', answer(404, 'text/plain', 'Not found'))).toBe('absent')
  expect(await publishedKeyState('alice@did.md', answer(200, 'application/octet-stream', 'KEY'))).toBe('present')
  expect(await publishedKeyState('alice@did.md', answer(200, 'text/plain', 'hello world!'))).toBe('unknown')
  expect(await publishedKeyState('alice@did.md', answer(500, 'text/plain', 'x'))).toBe('unknown')
  expect(await publishedKeyState('alice@did.md', (async () => { throw new Error('cors') }) as unknown as typeof fetch)).toBe('unknown')
})
