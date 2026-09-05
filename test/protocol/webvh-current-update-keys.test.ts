// resolveCurrentUpdateKeys: the same trust resolveEntries/resolve() already
// establish, just surfacing the CURRENT updateKeys instead of a
// WebvhDidDocument -- what mail-plugin's outbound submission auth verifies
// signatures against (mediator/mail-plugin/mail-submission-http.ts).
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { resolveCurrentUpdateKeys } from '../../src/client/identity/webvh/resolver.ts'
import { encodeMultikey, buildGenesisLog, withFetch } from './support/webvh-log-fixture.ts'

describe('resolveCurrentUpdateKeys', () => {
  test('returns the genesis updateKey for a freshly created identity', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    await withFetch(log, async () => {
      const keys = await resolveCurrentUpdateKeys(did)
      expect(keys).toEqual([encodeMultikey(rootPublicKey)])
    })
  })

  test('returns an empty array for a domain with no log', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    await withFetch(null, async () => {
      expect(await resolveCurrentUpdateKeys(did)).toEqual([])
    })
  })

  test('rejects an invalid log the same way resolve() does', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const tampered = [{ ...log[0]!, versionTime: '2099-01-01T00:00:00.000Z' }]
    await withFetch(tampered, async () => {
      await expect(resolveCurrentUpdateKeys(did)).rejects.toThrow()
    })
  })
})
