// AES OCB3 (RFC 7253), encryption only, with a 128-bit tag. It is what seals the session key inside a version 6 session key
// packet (RFC 9580 section 5.3.2) -- the form Delta Chat writes and reads for a password message. openpgp.js keeps its own
// OCB to itself, and the packet cannot be written without it.

const BLOCK = 16
const aesKey = (key: Uint8Array) => crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['encrypt'])

/** One AES block through the cipher: CBC with a zero IV is ECB for the first block. */
async function encipher(key: CryptoKey, block: Uint8Array): Promise<Uint8Array> {
  const out = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(BLOCK) }, key, block as BufferSource)
  return new Uint8Array(out, 0, BLOCK)
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length)
  for (let index = 0; index < a.length; index++) out[index] = a[index]! ^ b[index]!
  return out
}

// Doubling in GF(2^128): shift left one bit, and fold the carry in with 0x87.
function double(block: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK)
  for (let index = 0; index < BLOCK; index++) out[index] = ((block[index]! << 1) | (index + 1 < BLOCK ? block[index + 1]! >> 7 : 0)) & 0xff
  if (block[0]! & 0x80) out[BLOCK - 1]! ^= 0x87
  return out
}

function trailingZeros(n: number): number {
  let count = 0
  while ((n & 1) === 0) { n >>= 1; count++ }
  return count
}

/** `ciphertext || tag` for `plaintext` under `key` (16, 24 or 32 bytes), `nonce` (1 to 15 bytes) and the associated data. */
export async function ocbEncrypt(key: Uint8Array, nonce: Uint8Array, associated: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  if (nonce.length < 1 || nonce.length > 15) throw new TypeError('OCB nonce must be 1 to 15 bytes')
  const cipher = await aesKey(key)
  const lStar = await encipher(cipher, new Uint8Array(BLOCK))
  const lDollar = double(lStar)
  const lTable: Uint8Array[] = [double(lDollar)]
  const l = (index: number) => { while (lTable.length <= index) lTable.push(double(lTable[lTable.length - 1]!)); return lTable[index]! }

  // Nonce -> initial offset. The tag length is 128 bits, so its seven-bit field is zero.
  const padded = new Uint8Array(BLOCK)
  padded.set(nonce, BLOCK - nonce.length)
  padded[BLOCK - nonce.length - 1]! |= 1
  const bottom = padded[BLOCK - 1]! & 0x3f
  const top = Uint8Array.from(padded)
  top[BLOCK - 1]! &= 0xc0
  const ktop = await encipher(cipher, top)
  const stretch = new Uint8Array(24)
  stretch.set(ktop)
  for (let index = 0; index < 8; index++) stretch[BLOCK + index] = ktop[index]! ^ ktop[index + 1]!
  const shifted = new Uint8Array(BLOCK)
  const byteShift = bottom >> 3, bitShift = bottom & 7
  for (let index = 0; index < BLOCK; index++) {
    const high = stretch[index + byteShift]!, low = stretch[index + byteShift + 1] ?? 0
    shifted[index] = bitShift === 0 ? high : ((high << bitShift) | (low >> (8 - bitShift))) & 0xff
  }
  let offset: Uint8Array = shifted

  // Associated data hash.
  let sum: Uint8Array = new Uint8Array(BLOCK)
  let adOffset: Uint8Array = new Uint8Array(BLOCK)
  const adBlocks = Math.floor(associated.length / BLOCK)
  for (let index = 0; index < adBlocks; index++) {
    adOffset = xor(adOffset, l(trailingZeros(index + 1)))
    sum = xor(sum, await encipher(cipher, xor(associated.subarray(index * BLOCK, (index + 1) * BLOCK), adOffset)))
  }
  const adRest = associated.subarray(adBlocks * BLOCK)
  if (adRest.length > 0) {
    adOffset = xor(adOffset, lStar)
    const last = new Uint8Array(BLOCK)
    last.set(adRest)
    last[adRest.length] = 0x80
    sum = xor(sum, await encipher(cipher, xor(last, adOffset)))
  }

  // Encryption.
  const out = new Uint8Array(plaintext.length + BLOCK)
  let checksum: Uint8Array = new Uint8Array(BLOCK)
  const blocks = Math.floor(plaintext.length / BLOCK)
  for (let index = 0; index < blocks; index++) {
    const block = plaintext.subarray(index * BLOCK, (index + 1) * BLOCK)
    offset = xor(offset, l(trailingZeros(index + 1)))
    out.set(xor(offset, await encipher(cipher, xor(block, offset))), index * BLOCK)
    checksum = xor(checksum, block)
  }
  const rest = plaintext.subarray(blocks * BLOCK)
  if (rest.length > 0) {
    offset = xor(offset, lStar)
    const pad = await encipher(cipher, offset)
    out.set(xor(rest, pad.subarray(0, rest.length)), blocks * BLOCK)
    const last = new Uint8Array(BLOCK)
    last.set(rest)
    last[rest.length] = 0x80
    checksum = xor(checksum, last)
  }
  const tag = xor(await encipher(cipher, xor(xor(checksum, offset), lDollar)), sum)
  out.set(tag, plaintext.length)
  return out
}
