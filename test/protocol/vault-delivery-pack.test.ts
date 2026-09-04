import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/shared/protocol/canonical.ts'
import { decodeVaultDeliveryPack, encodeVaultDeliveryPack, type VaultDeliveryPackV1 } from '../../src/vault/delivery-pack.ts'

const pack: VaultDeliveryPackV1 = {
  version: 1,
  identityId: 'did:web:alice.example',
  objects: [{
    version: 1, identityId: 'did:web:alice.example', objectId: 'object-1', segmentId: 'segment-1',
    nonce: new Uint8Array([1, 2, 3]), ciphertext: new Uint8Array([4, 5, 6, 7]), ciphertextHash: new Uint8Array([8, 9]),
    plaintextLength: 2, aad: new Uint8Array([10]),
  }],
  events: [{
    version: 1, id: 'event-1', identityId: 'did:web:alice.example', actorDeviceId: 'device-a', actorSeq: 1,
    kind: 'keyword.set', targetIds: ['email-1'], objectRefs: ['object-1'], parents: ['event-0'],
    createdAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([11, 12]),
  }],
  keyWraps: [{
    version: 1, identityId: 'did:web:alice.example', selfGroupId: 'self-group-1', segmentId: 'segment-1',
    sourceEpoch: '1', recipientEpoch: '2', nonce: new Uint8Array([13]), aad: new Uint8Array([14]),
    wrappedSegmentKey: new Uint8Array([15, 16]), grantorDeviceId: 'device-a', grantedAt: '2026-08-21T00:00:00.000Z',
    signature: new Uint8Array([17]),
  }],
}

describe('vault delivery pack', () => {
  test('canonically packs immutable object, event, and MLS key-wrap records', () => {
    const encoded = encodeVaultDeliveryPack(pack)
    const decoded = decodeVaultDeliveryPack(encoded)
    expect(decoded).toEqual(pack)
    expect(equalBytes(encodeVaultDeliveryPack(decoded), encoded)).toBe(true)
  })

  test('rejects a syntactically valid but non-canonical wire body', () => {
    const encoded = encodeVaultDeliveryPack(pack)
    const trailingSpace = new Uint8Array(encoded.length + 1)
    trailingSpace.set(encoded)
    trailingSpace[encoded.length] = 0x20
    expect(() => decodeVaultDeliveryPack(trailingSpace)).toThrow('not canonical')
  })

  test('rejects an unrepresentable MLS epoch before accepting the wire body', () => {
    const wire = JSON.parse(new TextDecoder().decode(encodeVaultDeliveryPack(pack)))
    wire.keyWraps[0].recipientEpoch = '01'
    expect(() => decodeVaultDeliveryPack(new TextEncoder().encode(JSON.stringify(wire)))).toThrow('MLS epoch')
  })
})
