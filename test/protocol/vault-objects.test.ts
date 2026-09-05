import { describe, expect, test } from 'bun:test'
import { createSegmentKey, decryptVaultObject, encryptVaultObject } from '../../src/client/store/vault/objects.ts'

const text = new TextEncoder()

describe('vault objects', () => {
  test('encrypts once under a SegmentKey and verifies metadata before decrypting', async () => {
    const key = createSegmentKey()
    const plaintext = text.encode('message payload')
    const object = await encryptVaultObject(key, {
      segmentId: 'segment-1',
      plaintext,
      aad: text.encode('biset/vault/object/v1'),
    })

    expect(object.ciphertext).not.toEqual(plaintext)
    expect(object.nonce.length).toBe(12)
    expect(await decryptVaultObject(key, object)).toEqual(plaintext)
    await expect(decryptVaultObject(key, { ...object, aad: text.encode('wrong-aad') })).rejects.toThrow('ID does not match')
  })

  test('does not decrypt with a different SegmentKey', async () => {
    const object = await encryptVaultObject(createSegmentKey(), {
      segmentId: 'segment-1',
      plaintext: text.encode('message payload'),
      aad: new Uint8Array(),
    })
    await expect(decryptVaultObject(createSegmentKey(), object)).rejects.toThrow('decryption failed')
  })
})
