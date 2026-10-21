import { describe, expect, test } from 'vitest'
import { derivePgpKey } from '../src/client/pgp/derive.ts'
import { ownPgp } from '../src/client/pgp/own.ts'

const seed = () => crypto.getRandomValues(new Uint8Array(32))

describe('this identity\'s keys', () => {
  test('the current key is the one derived from the current seed; with no usable seed there is none', async () => {
    const current = seed()
    const keys = ownPgp('alice@did.md', { current: async () => current, all: async () => [current] })
    expect((await keys.current())!.fingerprint).toBe((await derivePgpKey(current, 'alice@did.md')).fingerprint)
    expect(await ownPgp('alice@did.md', { current: async () => undefined, all: async () => [] }).current()).toBeUndefined()
  })

  test('all lists the current generation first, then the earlier ones, each once', async () => {
    const [older, current, oldest] = [seed(), seed(), seed()]
    const keys = ownPgp('alice@did.md', { current: async () => current, all: async () => [oldest, current, older] })
    const fingerprints = (await keys.all()).map(key => key.fingerprint)
    expect(fingerprints).toEqual(await Promise.all([current, oldest, older].map(async value => (await derivePgpKey(value, 'alice@did.md')).fingerprint)))
    expect(new Set(fingerprints).size).toBe(3)
  })

  test('while the current seed is not usable yet, the earlier keys still open what they can', async () => {
    const older = seed()
    const keys = ownPgp('alice@did.md', { current: async () => undefined, all: async () => [older] })
    expect(await keys.current()).toBeUndefined()
    expect((await keys.all()).map(key => key.fingerprint)).toEqual([(await derivePgpKey(older, 'alice@did.md')).fingerprint])
  })
})
