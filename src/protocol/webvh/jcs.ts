// JSON Canonicalization Scheme (RFC 8785) — minimal implementation covering
// exactly what did:webvh log entries and Data Integrity proofs need: nested
// objects/arrays/strings/numbers/booleans/null. Key sort is UTF-16 code unit
// order (RFC8785 §3.2.3, which plain JS string comparison already gives —
// NOT code point or locale order). String/number serialization delegates to
// JSON.stringify, which matches ECMA-262 QuoteJSON/ToString for every value
// a DID document ever carries (no -0/NaN/Infinity, no exotic bigints).
export function canonicalize(value: unknown): string {
  return serialize(value)
}

function serialize(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') return serializeNumber(value)
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort(compareUtf16)
    const parts = keys.map(k => `${JSON.stringify(k)}:${serialize(obj[k])}`)
    return `{${parts.join(',')}}`
  }
  throw new Error(`canonicalize: unsupported value type ${typeof value}`)
}

function compareUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new Error('canonicalize: non-finite numbers are not representable in JSON')
  if (Object.is(n, -0)) return '0' // RFC8785 §3.2.2.3: -0 serializes as "0"
  return JSON.stringify(n)
}
