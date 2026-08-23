import { AeadAlgorithm } from "./aead.js"
import { KdfAlgorithm } from "./kdf.js"
import { KemAlgorithm } from "./kem.js"
import { varLenDataEncoder } from "../codec/variableLength.js"
import { composeBufferEncoders, encode } from "../codec/tlsEncoder.js"

// biset: HPKE keys were WebCrypto `CryptoKey`s because the implementation was
// @hpke/core, which is built on WebCrypto. This fork implements HPKE directly
// over @noble (crypto/implementation/noble/hpke.ts), where a key is its bytes
// and nothing else. They stay nominal types rather than bare Uint8Arrays so a
// public key can never be passed where a private one is expected — the one
// mistake the CryptoKey types did usefully prevent.
/** @public */
export type PublicKey = { readonly bytes: Uint8Array; readonly keyType: "public" }

export type SecretKey = { readonly bytes: Uint8Array; readonly keyType: "secret" }

/** @public */
export type PrivateKey = { readonly bytes: Uint8Array; readonly keyType: "private" }

/** @public */
export interface HpkeAlgorithm {
  kem: KemAlgorithm
  kdf: KdfAlgorithm
  aead: AeadAlgorithm
}

export function encryptWithLabel(
  publicKey: PublicKey,
  label: string,
  context: Uint8Array,
  plaintext: Uint8Array,
  hpke: Hpke,
): Promise<{ ct: Uint8Array; enc: Uint8Array }> {
  return hpke.seal(
    publicKey,
    plaintext,
    encode(composeBufferEncoders([varLenDataEncoder, varLenDataEncoder]))([
      new TextEncoder().encode(`MLS 1.0 ${label}`),
      context,
    ]),
    new Uint8Array(),
  )
}

export function decryptWithLabel(
  privateKey: PrivateKey,
  label: string,
  context: Uint8Array,
  kemOutput: Uint8Array,
  ciphertext: Uint8Array,
  hpke: Hpke,
): Promise<Uint8Array> {
  return hpke.open(
    privateKey,
    kemOutput,
    ciphertext,
    encode(composeBufferEncoders([varLenDataEncoder, varLenDataEncoder]))([
      new TextEncoder().encode(`MLS 1.0 ${label}`),
      context,
    ]),
  )
}

/** @public */
export interface Hpke {
  open(
    privateKey: PrivateKey,
    kemOutput: Uint8Array,
    ciphertext: Uint8Array,
    info: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>
  seal(
    publicKey: PublicKey,
    plaintext: Uint8Array,
    info: Uint8Array,
    aad?: Uint8Array,
  ): Promise<{ ct: Uint8Array; enc: Uint8Array }>
  importPrivateKey(k: Uint8Array): Promise<PrivateKey>
  importPublicKey(k: Uint8Array): Promise<PublicKey>
  exportPublicKey(k: PublicKey): Promise<Uint8Array>
  exportPrivateKey(k: PrivateKey): Promise<Uint8Array>
  encryptAead(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array | undefined,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>
  decryptAead(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array | undefined,
    ciphertext: Uint8Array,
  ): Promise<Uint8Array>
  exportSecret(
    publicKey: PublicKey,
    exporterContext: Uint8Array,
    length: number,
    info: Uint8Array,
  ): Promise<{ enc: Uint8Array; secret: Uint8Array }>
  importSecret(
    privateKey: PrivateKey,
    exporterContext: Uint8Array,
    kemOutput: Uint8Array,
    length: number,
    info: Uint8Array,
  ): Promise<Uint8Array>
  deriveKeyPair(ikm: Uint8Array): Promise<{ privateKey: PrivateKey; publicKey: PublicKey }>
  generateKeyPair(): Promise<{ privateKey: PrivateKey; publicKey: PublicKey }>
  keyLength: number
  nonceLength: number
}
