// Zooko Wilcox-O'Hearn's human-oriented base32 — port of jmapsmtp's
// `crates/jmapserver/src/zbase32.rs` (same alphabet, same bit-packing),
// needed here for the same reason as there: the SCID<->localpart projection
// (scid-localpart.ts) has to be computable identically on both sides, since
// a client that could not compute its own resulting address would have to
// ask the relay for it before it could tell the user what they just got.
//
// Not RFC 4648's base32 alphabet — that one distinguishes case, which is
// exactly the property this projection needs to NOT have (scid-localpart.ts
// explains why).
const ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'

export function encode(data: Uint8Array): string {
  let out = ''
  let bits = 0
  let value = 0
  for (const b of data) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 31]
  }
  return out
}

/** Decodes exactly `byteLen` bytes, discarding the encoder's trailing
 * padding bits. `null` when the input has a character outside the alphabet,
 * or does not yield exactly that many bytes — mirrors the Rust decoder's own
 * contract byte for byte. */
export function decode(s: string, byteLen: number): Uint8Array | null {
  const out: number[] = []
  let bits = 0
  let value = 0
  for (const c of s) {
    const idx = ALPHABET.indexOf(c)
    if (idx < 0) return null
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bits -= 8
      if (out.length < byteLen) out.push((value >>> bits) & 0xff)
    }
  }
  return out.length === byteLen ? new Uint8Array(out) : null
}
