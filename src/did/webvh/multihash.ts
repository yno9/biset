// Multihash (multiformats/multihash), SHA-256 only — did:webvh v1.0 permits
// no other hash algorithm (method parameter "did:webvh:1.0"), so this
// implements exactly that fixed shape rather than the general varint-coded
// table. Both the function code (0x12) and digest length (0x20 = 32) happen
// to be < 128, so each is a one-byte unsigned-LEB128 varint — no varint
// decoder needed here.
import { sha256 } from '@noble/hashes/sha2.js'

const SHA256_CODE = 0x12
const SHA256_LEN = 32

export function multihashSha256(data: Uint8Array): Uint8Array {
  const digest = sha256(data)
  const out = new Uint8Array(2 + SHA256_LEN)
  out[0] = SHA256_CODE
  out[1] = SHA256_LEN
  out.set(digest, 2)
  return out
}

export function isSha256Multihash(bytes: Uint8Array): boolean {
  return bytes.length === SHA256_LEN + 2 && bytes[0] === SHA256_CODE && bytes[1] === SHA256_LEN
}
