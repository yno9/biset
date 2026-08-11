// z-base-32 (human-oriented base32, Zooko Wilcox-O'Hearn), used by did:dht to
// encode the raw ed25519 public key into the method-specific id.
// https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
const ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'

export function zbase32Encode(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]
  return out
}

const INV = (() => {
  const m = new Int8Array(128).fill(-1)
  for (let i = 0; i < ALPHABET.length; i++) m[ALPHABET.charCodeAt(i)] = i
  return m
})()

// Decodes to exactly `byteLen` bytes (32 for an ed25519 identity key), ignoring
// the trailing sub-byte padding bits the encoder appended.
export function zbase32Decode(s: string, byteLen: number): Uint8Array {
  const out = new Uint8Array(byteLen)
  let bits = 0, value = 0, oi = 0
  for (const ch of s) {
    const v = INV[ch.charCodeAt(0)]
    if (v < 0) throw new Error(`invalid z-base-32 char "${ch}"`)
    value = (value << 5) | v
    bits += 5
    if (bits >= 8) {
      bits -= 8
      if (oi < byteLen) out[oi++] = (value >>> bits) & 0xff
    }
  }
  if (oi !== byteLen) throw new Error(`z-base-32 decoded ${oi} bytes, expected ${byteLen}`)
  return out
}
