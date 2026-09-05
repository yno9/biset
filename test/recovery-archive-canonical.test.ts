import { describe, expect, test } from 'bun:test'
import { canonicalBytes, type CanonicalValue } from '../src/shared/protocol/canonical.ts'
import { buildVaultManifest } from '../src/client/store/vault/manifest.ts'
import { decodeRecoveryArchiveSnapshot, encodeRecoveryArchiveSnapshot } from '../src/client/store/vault/recovery-archive.ts'

const identityId = 'did:webvh:test:example.test'
const createdAt = '2026-08-29T00:00:00.000Z'
const objectId = 'obj_test'
const storedObject = {
  version: 1 as const, identityId, objectId, segmentId: 'seg_test', nonce: new Uint8Array(12),
  ciphertext: new Uint8Array([1]), ciphertextHash: new Uint8Array(32), plaintextLength: 0, aad: new Uint8Array([2]),
}
const snapshot = {
  version: 1 as const, identityId, manifest: buildVaultManifest(identityId, [], [objectId], createdAt),
  events: [], objects: [storedObject], segmentKeys: [{ segmentId: 'seg_test', key: new Uint8Array(32) }], createdAt,
}

describe('Recovery Archive canonical storage boundary', () => {
  test('does not serialize the IndexedDB-only object partition key', () => {
    const encoded = encodeRecoveryArchiveSnapshot(snapshot)
    const wire = JSON.parse(new TextDecoder().decode(encoded)) as { objects: Array<Record<string, unknown>> }
    expect(wire.objects[0]!.identityId).toBeUndefined()
    expect(decodeRecoveryArchiveSnapshot(encoded).objects[0]).not.toHaveProperty('identityId')
  })

  test('reads the exact legacy canonical shape while rejecting arbitrary extensions', () => {
    const current = JSON.parse(new TextDecoder().decode(encodeRecoveryArchiveSnapshot(snapshot))) as Record<string, unknown>
    const objects = current.objects as Array<Record<string, unknown>>
    objects[0]!.identityId = identityId
    const legacy = canonicalBytes(current as CanonicalValue)
    expect(decodeRecoveryArchiveSnapshot(legacy).objects[0]).not.toHaveProperty('identityId')

    objects[0]!.unexpected = true
    expect(() => decodeRecoveryArchiveSnapshot(canonicalBytes(current as CanonicalValue))).toThrow('unexpected fields')
  })
})
