import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToBase64url } from './base64.ts'

export type CanonicalValue =
  | null
  | boolean
  | number
  | string
  | CanonicalValue[]
  | { [key: string]: CanonicalValue }

const encoder = new TextEncoder()

/**
 * Stable JSON for signed protocol envelopes. This is deliberately narrower
 * than JavaScript values: binary data is represented outside this function and
 * undefined, NaN, Infinity, bigint, Date, Map, and custom instances are
 * rejected instead of being silently coerced.
 */
export function canonicalJson(value: CanonicalValue): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON does not allow non-finite numbers')
    return Object.is(value, -0) ? '0' : JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`

  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('canonical JSON only accepts plain objects')
  }
  const entries = Object.entries(value).sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
  return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(',')}}`
}

export function canonicalBytes(value: CanonicalValue): Uint8Array {
  return encoder.encode(canonicalJson(value))
}

export function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return sha256(bytes)
}

/** `label` is included in every hash preimage to prevent cross-protocol use. */
export function domainHash(label: string, body: Uint8Array): string {
  if (!/^[a-z0-9][a-z0-9./:-]{0,127}$/.test(label)) {
    throw new TypeError('invalid hash domain label')
  }
  const labelBytes = encoder.encode(label)
  const input = new Uint8Array(labelBytes.length + 1 + body.length)
  input.set(labelBytes)
  input[labelBytes.length] = 0
  input.set(body, labelBytes.length + 1)
  return `sha256:${bytesToBase64url(sha256Bytes(input))}`
}

export function canonicalHash(label: string, value: CanonicalValue): string {
  return domainHash(label, canonicalBytes(value))
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let difference = 0
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index]
  return difference === 0
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}
