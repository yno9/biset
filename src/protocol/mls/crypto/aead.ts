/** @public */
// biset: narrowed to the single ciphersuite this fork implements (crypto/ciphersuite.ts).
export type AeadAlgorithm = "AES128GCM"

export interface Aead {
  encrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>
  decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>
}
