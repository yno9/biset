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
