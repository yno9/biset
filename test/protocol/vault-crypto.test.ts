import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/shared/protocol/canonical.ts'
import { createSegmentKeyWrap, unwrapSegmentKey, type SegmentKeyWrapSigner } from '../../src/vault/crypto.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'

const signer: SegmentKeyWrapSigner = {
  deviceId: 'device-a',
  async sign(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBuffer(bytes)))
  },
  async verify(deviceId, bytes, signature) {
    if (deviceId !== this.deviceId) return false
    return equalBytes(signature, await this.sign(bytes))
  },
}

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
  test('releases a SegmentKey only to a verifier with the current VEK', async () => {
    const vek = createSegmentKey()
    const segmentKey = createSegmentKey()
    const wrap = await createSegmentKeyWrap(vek, segmentKey, draft, signer)

    expect(wrap.nonce).toHaveLength(12)
    expect(wrap.wrappedSegmentKey).not.toEqual(segmentKey)
    expect(await unwrapSegmentKey(vek, wrap, signer)).toEqual(segmentKey)
    await expect(unwrapSegmentKey(createSegmentKey(), wrap, signer)).rejects.toThrow('decryption failed')
  })

  test('rejects a signed wrap when its protected metadata or signature changes', async () => {
    const wrap = await createSegmentKeyWrap(createSegmentKey(), createSegmentKey(), draft, signer)
    await expect(unwrapSegmentKey(createSegmentKey(), { ...wrap, recipientEpoch: '14' }, signer)).rejects.toThrow('AAD does not match')

    const changedSignature = wrap.signature.slice()
    changedSignature[0] ^= 0xff
    await expect(unwrapSegmentKey(createSegmentKey(), { ...wrap, signature: changedSignature }, signer)).rejects.toThrow('signature is invalid')
  })
})

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)
  return copy.buffer
}
