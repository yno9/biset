// Replays every fixed vector in src/protocol/test-vectors.ts against the
// live canonicalJson/canonicalBytes/sha256Bytes implementation -- this is
// the test PLAN.md §2.1 asks for: proof that the vectors are not just
// documentation but an executable, current contract. An independent
// (non-TypeScript) implementation replaying the same `value`s should
// reproduce the same `json` text and `sha256Base64url` hash byte for byte.
import { describe, expect, test } from 'bun:test'
import { canonicalJson, canonicalBytes, sha256Bytes, bytesToBase64url } from '../../src/shared/protocol/canonical.ts'
import { CANONICAL_JSON_VECTORS } from '../../src/shared/protocol/test-vectors.ts'

describe('canonical JSON V1 cross-language vectors', () => {
  for (const vector of CANONICAL_JSON_VECTORS) {
    test(vector.name, () => {
      expect(canonicalJson(vector.value)).toBe(vector.json)
      expect(bytesToBase64url(sha256Bytes(canonicalBytes(vector.value)))).toBe(vector.sha256Base64url)
    })
  }

  test('rejects non-finite numbers rather than silently coercing them', () => {
    expect(() => canonicalJson(Number.NaN)).toThrow('non-finite')
    expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow('non-finite')
    expect(() => canonicalJson(Number.NEGATIVE_INFINITY)).toThrow('non-finite')
  })

  test('every vector name is unique (a duplicate would silently shadow test coverage)', () => {
    const names = CANONICAL_JSON_VECTORS.map(vector => vector.name)
    expect(new Set(names).size).toBe(names.length)
  })
})
