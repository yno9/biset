import { Signature, SignatureAlgorithm } from "./signature.js"
import { Hash, HashAlgorithm } from "./hash.js"
import { Kdf } from "./kdf.js"
import { Hpke, HpkeAlgorithm } from "./hpke.js"
import { contramapBufferEncoder, BufferEncoder, encode, Encoder } from "../codec/tlsEncoder.js"
import { decodeUint16, uint16Encoder } from "../codec/number.js"
import { Decoder, mapDecoderOption } from "../codec/tlsDecoder.js"
import { openEnumNumberEncoder, openEnumNumberToKey, reverseMap } from "../util/enumHelpers.js"
import { Rng } from "./rng.js"

/** @public */
export interface CiphersuiteImpl {
  hash: Hash
  hpke: Hpke
  signature: Signature
  kdf: Kdf
  rng: Rng
  name: CiphersuiteName
}

/** @public */
// biset: only the one ciphersuite this fork implements
// (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, RFC 9420's
// mandatory-to-implement suite). Every other entry is deleted rather than left
// unimplemented: this map is also what `defaultCapabilities` advertises, and
// advertising a suite the build cannot perform invites a peer to pick it.
// A KeyPackage or GroupContext naming another suite now fails to decode, which
// is the correct answer for a client that genuinely cannot speak it.
export const ciphersuites = {
  MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519: 1,
} as const

/** @public */
export type CiphersuiteName = keyof typeof ciphersuites
export type CiphersuiteId = (typeof ciphersuites)[CiphersuiteName]

export const ciphersuiteEncoder: BufferEncoder<CiphersuiteName> = contramapBufferEncoder(
  uint16Encoder,
  openEnumNumberEncoder(ciphersuites),
)

export const encodeCiphersuite: Encoder<CiphersuiteName> = encode(ciphersuiteEncoder)

export const decodeCiphersuite: Decoder<CiphersuiteName> = mapDecoderOption(
  decodeUint16,
  openEnumNumberToKey(ciphersuites),
)

export function getCiphersuiteNameFromId(id: CiphersuiteId): CiphersuiteName {
  return reverseMap(ciphersuites)[id] as CiphersuiteName
}

export function getCiphersuiteFromId(id: CiphersuiteId): Ciphersuite {
  return ciphersuiteValues[id]
}

/** @public */
export function getCiphersuiteFromName(name: CiphersuiteName): Ciphersuite {
  return ciphersuiteValues[ciphersuites[name]]
}

const ciphersuiteValues: Record<CiphersuiteId, Ciphersuite> = {
  1: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-X25519-HKDF-SHA256",
      aead: "AES128GCM",
      kdf: "HKDF-SHA256",
    },
    signature: "Ed25519",
    name: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
  },
}

/** @public */
export type Ciphersuite = {
  hash: HashAlgorithm
  hpke: HpkeAlgorithm
  signature: SignatureAlgorithm
  name: CiphersuiteName
}
