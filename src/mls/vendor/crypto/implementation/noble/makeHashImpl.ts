// biset: SHA-256 only — see crypto/ciphersuite.ts.
import { Hash } from "../../hash.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { hmac } from "@noble/hashes/hmac.js"
import { constantTimeEqual } from "../../../util/constantTimeCompare.js"

export function makeHashImpl(): Hash {
  return {
    async digest(data) {
      return sha256(data)
    },
    async mac(key, data) {
      return hmac(sha256, key, data)
    },
    async verifyMac(key, mac, data) {
      return constantTimeEqual(mac, await this.mac(key, data))
    },
  }
}
