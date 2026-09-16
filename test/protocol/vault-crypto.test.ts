import { describe, expect, test } from 'bun:test'
import { createSegmentKeyWrap, unwrapSegmentKey } from '../../src/client/store/vault/crypto.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'

const draft = {
  identityId: 'did:web:alice.example',
  selfGroupId: 'self-group-alice',
  segmentId: 'segment-2026-08',
  sourceEpoch: '12',
  recipientEpoch: '13',
  grantorDeviceId: 'device-a',
  grantedAt: '2026-08-21T00:00:00.000Z',
}

describe('SegmentKey wraps', () => {
  test('releases a SegmentKey only to a holder of the current VCK', async () => {
    const vek = createSegmentKey()
    const segmentKey = createSegmentKey()
    const wrap = await createSegmentKeyWrap(vek, segmentKey, draft)

    expect(wrap.nonce).toHaveLength(12)
    expect(wrap.wrappedSegmentKey).not.toEqual(segmentKey)
    expect(await unwrapSegmentKey(vek, wrap)).toEqual(segmentKey)
    await expect(unwrapSegmentKey(createSegmentKey(), wrap)).rejects.toThrow('decryption failed')
  })

  test('rejects a wrap when its protected metadata changes', async () => {
    const vek = createSegmentKey()
    const wrap = await createSegmentKeyWrap(vek, createSegmentKey(), draft)
    await expect(unwrapSegmentKey(vek, { ...wrap, recipientEpoch: '14' })).rejects.toThrow('AAD does not match')
  })
})
