// biset: HKDF over @noble, replacing @hpke/core's KdfInterface. Only
// HKDF-SHA256 exists here — see crypto/ciphersuite.ts.
import { extract, expand } from "@noble/hashes/hkdf.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { Kdf } from "../../kdf.js"

export function makeKdfImpl(): Kdf {
  return {
    async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
      return extract(sha256, ikm, salt)
    },
    async expand(prk: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
      return expand(sha256, prk, info, len)
    },
    size: 32,
  }
}
