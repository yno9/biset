// biset: Ed25519 over @noble only.
//
// Upstream preferred WebCrypto when available and fell back to @noble. That
// fallback is not merely a second code path: WebCrypto's Ed25519 exports
// private keys as PKCS#8 while @noble uses the raw 32-byte scalar, so which
// branch ran decided the FORMAT of the signature private key stored in every
// serialized group state. A state written on one runtime could then fail to
// sign on another. One implementation, one format: raw 32 bytes.
import { ed25519 } from "@noble/curves/ed25519.js"
import { Signature } from "../../signature.js"

export async function makeNobleSignatureImpl(): Promise<Signature> {
  return {
    async sign(signKey, message) {
      return ed25519.sign(message, signKey)
    },
    async verify(publicKey, message, signature) {
      return ed25519.verify(signature, message, publicKey)
    },
    async keygen() {
      const signKey = ed25519.utils.randomSecretKey()
      return { signKey, publicKey: ed25519.getPublicKey(signKey) }
    },
  }
}
