// The one place base64 is encoded and decoded.
//
//   bytesToBase64url / base64urlToBytes  unpadded base64url, strict: what this code base writes into
//                                        signed or hashed values, where one value must have one spelling.
//   bytesToBase64 / base64ToBytes        standard base64 out; in, either alphabet, padded or not --
//                                        for what other implementations send (JWE, MIME, Autocrypt).
import { base64, base64urlnopad } from '@scure/base'

export function bytesToBase64url(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes)
}

export function base64urlToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) throw new TypeError('invalid base64url value')
  // Past the checks above, the only thing left to refuse is a last character with bits that no byte uses.
  try { return base64urlnopad.decode(value) } catch { throw new TypeError('invalid base64url trailing bits') }
}

export function bytesToBase64(bytes: Uint8Array): string {
  return base64.encode(bytes)
}

export function base64ToBytes(value: string): Uint8Array {
  const standard = value.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(standard + '='.repeat((4 - standard.length % 4) % 4)), char => char.charCodeAt(0))
}

export function textToBase64url(text: string): string {
  return bytesToBase64url(new TextEncoder().encode(text))
}

export function base64ToText(value: string): string {
  return new TextDecoder().decode(base64ToBytes(value))
}
