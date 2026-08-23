// PLAN.md §2.1's "canonical JSON V1 の値域・Unicode・number の
// cross-language test vector を src/protocol/test-vectors.ts に固定する".
//
// Fixed input/output pairs for `canonicalJson`/`canonicalBytes` +
// SHA-256 — not just a regression harness for this TypeScript
// implementation, but the reference an independent implementation in
// another language (a Rust/Go core, say) can replay byte-for-byte to prove
// it produces identical `canonicalBytes`/`canonicalHash` output. Every
// `json`/`sha256Base64url` value here was generated FROM the real
// `canonicalJson`/`sha256Bytes`/`bytesToBase64url` functions
// (protocol/canonical.ts) at the time this file was written — this file
// pins that behavior; it does not itself define it. Changing `canonicalJson`
// in a way that changes any of these values is a wire-format break, not a
// refactor — the test iterating over this table
// (test/protocol/canonical-json-vectors.test.ts) exists to catch exactly that.
import type { CanonicalValue } from './canonical.ts'

export interface CanonicalJsonVector {
  name: string
  value: CanonicalValue
  /** Exact expected output of `canonicalJson(value)`. */
  json: string
  /** `bytesToBase64url(sha256Bytes(canonicalBytes(value)))` — pins the hash algorithm and encoding too, not just the JSON text. */
  sha256Base64url: string
}

export const CANONICAL_JSON_VECTORS: readonly CanonicalJsonVector[] = [
  { name: 'null', value: null, json: 'null', sha256Base64url: 'dCNOmK_nSY-12vHzasLXiswzlGT5UHA7jAGYkvmCuQs' },
  { name: 'true', value: true, json: 'true', sha256Base64url: 'tb6kG2xiP3wJ8b8k3K5Y66s8DN2QrZZrxDpFtEhn4Ss' },
  { name: 'false', value: false, json: 'false', sha256Base64url: '_LzxZZCN0YqeSff_J4EBdtuOn2O0NSITdBZkJFIk-Ko' },
  { name: 'empty string', value: '', json: '""', sha256Base64url: 'Eq4yyx7ALQHto1gbEnwf7jsNxTVy7WuvI5choD2C4SY' },
  { name: 'empty array', value: [], json: '[]', sha256Base64url: 'T1PNoYwrqgwDVLtfmj7L5e0Sq02OEbqHPC8RFhICuUU' },
  { name: 'empty object', value: {}, json: '{}', sha256Base64url: 'RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o' },

  // Number value domain -- integers, the -0/0 collapse, fractional values,
  // and both directions of exponent notation JSON.stringify itself chooses.
  { name: 'zero', value: 0, json: '0', sha256Base64url: 'X-zrZv_IbzjZUnhsbWlsecLbwjndTpG0ZynXOif7V-k' },
  { name: 'negative zero collapses to zero', value: -0, json: '0', sha256Base64url: 'X-zrZv_IbzjZUnhsbWlsecLbwjndTpG0ZynXOif7V-k' },
  { name: 'positive integer', value: 42, json: '42', sha256Base64url: 'c0dctApWjo2ooEXO0RATfhWfiQrE2og7axfcZRs6gEk' },
  { name: 'negative integer', value: -42, json: '-42', sha256Base64url: '_sgABt8FQlSbTLqvuJh-7gC7Sbyjlu7-msi-W1ko6PY' },
  { name: 'max safe integer', value: Number.MAX_SAFE_INTEGER, json: '9007199254740991', sha256Base64url: '9AtCPC3ZX_Ky8CfiIgj0OM9yQoYuXnRoYOaXMIya3SY' },
  { name: 'min safe integer', value: Number.MIN_SAFE_INTEGER, json: '-9007199254740991', sha256Base64url: 'TJM6RWu48umJSy0LJkgEOc1y1S-4ony_j9fzI_IseBU' },
  { name: 'fractional number', value: 1.5, json: '1.5', sha256Base64url: 'nymhMEOLgRcLkqQmUPmpQpHsrWC9R68qOIbnX39yhyU' },
  { name: 'small fractional number', value: 0.1, json: '0.1', sha256Base64url: 'FL5LRfGODYxntPcZtRRO7ohJfkE3CdEdhbCW2OI0YxA' },
  { name: 'tiny exponent-notation number', value: 1e-7, json: '1e-7', sha256Base64url: 'WzPgLyxRA6BdMva6nLBYKURSv785OWf2i7MMG9y7qyI' },
  { name: 'huge exponent-notation number', value: 1e21, json: '1e+21', sha256Base64url: 'JBxGQ_pwsdzeEgW3G-TjvrsX6fiAyOGjPQ6tbCcnHTw' },

  // String value domain -- ASCII, JSON-significant escapes, control
  // characters, and Unicode across the BMP/astral/combining-sequence range.
  // canonicalJson does NOT escape non-ASCII (JSON.stringify's own default),
  { name: 'decomposed combining sequence (e + U+0301, not NFC-normalized to precomposed \u00e9)', value: 'e\u0301', json: '"e\u0301"', sha256Base64url: 'PWjOIfKJmkdXE82-dWK6m9trHf3orx8iG9_0oJNbU7I' },
  // decomposed, byte for byte, which is why that vector is included: an
  // implementation that normalizes to NFC would diverge here.
  { name: 'ascii string', value: 'hello', json: '"hello"', sha256Base64url: 'Wqdirjg_u3J688ejbUlApbjECpiUUtIwT8lY_z81Tno' },
  { name: 'quote and backslash', value: 'a"b\\c', json: '"a\\"b\\\\c"', sha256Base64url: 'KeQJ50RivgmCd9FCjlLiLNeC5zqfULT08m5lJ6tYPso' },
  { name: 'JSON-escaped control characters', value: 'a\nb\tc', json: '"a\\nb\\tc"', sha256Base64url: 'Lc2zEB6wcgf4jFoufyCcQhnvaqTAZjJRfOq5j1I5ego' },
  { name: 'embedded null character', value: 'a\x00b', json: '"a\\u0000b"', sha256Base64url: 'nbGK9zYM1dA73fajQ5W8viqaDHnvfEleW9FJw8SQ3v4' },
  { name: 'BMP unicode (not \\u-escaped)', value: '日本語', json: '"日本語"', sha256Base64url: '0rlObmZEg7vwTYCQKrwjVSeraM7PSI6KviIRKm3WK9Q' },
  { name: 'astral-plane emoji (surrogate pair)', value: '😀', json: '"😀"', sha256Base64url: 'egxQuSQ0sBVUX-k6tyPbLUss3RSkQUBWJKnOi-KfHVo' },

  // Structural domain -- key sort order is plain UTF-16 code-unit order, not
  // locale-aware collation ('Z' < 'a' < 'b' here, not 'a' < 'b' < 'Z').
  { name: 'object keys sorted by code unit, not locale', value: { b: 1, a: 2, Z: 3 }, json: '{"Z":3,"a":2,"b":1}', sha256Base64url: 'ZQo7U2KX4LSsYuM2rsN4w_wVeVLdWx4FEAzNganI9dA' },
  { name: 'nested array/object', value: { list: [1, { x: null }, 'y'] }, json: '{"list":[1,{"x":null},"y"]}', sha256Base64url: 'l_ob7HauS7SXTs88Hok_wxE2lRnrtp1nSB6v-wEgrP4' },
]
