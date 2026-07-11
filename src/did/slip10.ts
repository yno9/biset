// SLIP-0010 ed25519 key derivation (hardened-only — ed25519 has no
// non-hardened derivation, per spec: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'

export interface Slip10Node { key: Uint8Array; chainCode: Uint8Array }

const ED25519_SEED_KEY = new TextEncoder().encode('ed25519 seed')
const HARDENED = 0x80000000

function ser32(i: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, i, false)
  return b
}

export function masterNode(seed: Uint8Array): Slip10Node {
  const I = hmac(sha512, ED25519_SEED_KEY, seed)
  return { key: I.slice(0, 32), chainCode: I.slice(32, 64) }
}

function deriveHardenedChild(parent: Slip10Node, index: number): Slip10Node {
  const data = new Uint8Array(1 + 32 + 4)
  data[0] = 0
  data.set(parent.key, 1)
  data.set(ser32(index + HARDENED), 33)
  const I = hmac(sha512, parent.chainCode, data)
  return { key: I.slice(0, 32), chainCode: I.slice(32, 64) }
}

// path like "m/0'/2'" — every segment must be hardened (trailing ').
export function derivePath(seed: Uint8Array, path: string): Slip10Node {
  const segments = path.split('/').filter(s => s.length > 0 && s !== 'm')
  let node = masterNode(seed)
  for (const seg of segments) {
    if (!seg.endsWith("'")) throw new Error(`ed25519 SLIP-0010 requires hardened segments, got "${seg}"`)
    const index = Number.parseInt(seg.slice(0, -1), 10)
    if (!Number.isInteger(index) || index < 0 || index >= HARDENED) throw new Error(`invalid path segment "${seg}"`)
    node = deriveHardenedChild(node, index)
  }
  return node
}
