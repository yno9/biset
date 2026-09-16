import { describe, expect, test } from 'bun:test'
import { createSegmentKeyWrap } from '../../src/client/store/vault/crypto.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'
import { StoredSegmentKeyResolver } from '../../src/client/store/vault/segment-key-resolver.ts'

describe('StoredSegmentKeyResolver', () => {
  test('uses only the current MLS epoch wrap and clears its transient VEK', async () => {
    const vek = createSegmentKey()
    const segmentKey = createSegmentKey()
    let derivedVek: Uint8Array | undefined
    const wrap = await createSegmentKeyWrap(vek, segmentKey, {
      identityId: 'did:web:alice.example', selfGroupId: 'self-group-a', segmentId: 'segment-1', sourceEpoch: '7', recipientEpoch: '9', grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z',
    })
    const resolver = new StoredSegmentKeyResolver(
      { async readSegmentKeyWrap() { return wrap } },
      {
        async currentVaultEpoch() { return { selfGroupId: 'self-group-a', epoch: '9' } },
        async deriveVaultEpochKey() {
          derivedVek = vek.slice()
          return derivedVek
        },
      },
    )
    expect(await resolver.resolveSegmentKey('did:web:alice.example', 'segment-1')).toEqual(segmentKey)
    expect(derivedVek).toEqual(new Uint8Array(32))
  })

  test('requires a current-epoch grant rather than falling back to an old wrap', async () => {
    const resolver = new StoredSegmentKeyResolver(
      { async readSegmentKeyWrap() { return undefined } },
      {
        async currentVaultEpoch() { return { selfGroupId: 'self-group-a', epoch: '10' } },
        async deriveVaultEpochKey() { throw new Error('must not derive without a current wrap') },
      },
    )
    await expect(resolver.resolveSegmentKey('did:web:alice.example', 'segment-1')).rejects.toThrow('restore grant is required')
  })
})
