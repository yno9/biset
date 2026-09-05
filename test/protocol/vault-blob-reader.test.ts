import { describe, expect, test } from 'bun:test'
import { VaultObjectBlobReader } from '../../src/client/store/vault/blob-reader.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/client/store/vault/objects.ts'

const text = new TextEncoder()

describe('VaultObjectBlobReader', () => {
  test('authenticates and decrypts a vault object before serving its local JMAP range', async () => {
    const segmentKey = createSegmentKey()
    const object = await encryptVaultObject(segmentKey, {
      segmentId: 'segment-1',
      plaintext: text.encode('hello vault'),
      aad: text.encode('blob-aad'),
    })
    const reader = new VaultObjectBlobReader(
      { async readObject() { return { ...object, identityId: 'did:web:alice.example' } } },
      { async resolveSegmentKey() { return segmentKey } },
    )
    expect(new TextDecoder().decode(await reader.download('did:web:alice.example', object.objectId, { start: 6, end: 10 }))).toBe('vault')
  })

  test('does not return bytes when the object fails cryptographic verification', async () => {
    const segmentKey = createSegmentKey()
    const object = await encryptVaultObject(segmentKey, {
      segmentId: 'segment-1',
      plaintext: text.encode('hello vault'),
      aad: new Uint8Array(),
    })
    const reader = new VaultObjectBlobReader(
      { async readObject() { return { ...object, identityId: 'did:web:alice.example', ciphertext: new Uint8Array([1]) } } },
      { async resolveSegmentKey() { return segmentKey } },
    )
    await expect(reader.download('did:web:alice.example', object.objectId)).rejects.toThrow('ID does not match')
  })
})
