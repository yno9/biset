// biset: HPKE (RFC 9180) over @noble, replacing @hpke/core.
//
// Upstream ts-mls delegates HPKE to `@hpke/core`, which is ~687KB minified —
// five times the size of the MLS implementation it supports — because it
// carries every KEM, KDF and AEAD the HPKE registry defines. biset uses
// exactly one MLS ciphersuite, which pins exactly one HPKE suite:
//
//     DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
//
// Its primitives are already in the `@noble/*` packages the app bundles for
// everything else, so this file is the whole of what @hpke/core was providing.
//
// **Base mode only.** MLS never uses PSK or authenticated modes (RFC 9420 uses
// `SetupBaseS`/`SetupBaseR` throughout), so mode 0x00 is the only one
// implemented rather than the only one exercised — an unimplemented mode
// cannot be reached by accident.
//
// **Single-shot only.** Every HPKE use in MLS seals or opens exactly one
// message per context, so the sequence number is always 0 and no nonce
// sequencing state exists here. That is not a simplification of the spec's
// requirements but of its generality: the nonce-reuse hazard that sequencing
// exists to prevent cannot arise when a context is used once.
//
// Correctness is checked two ways, both in `test/mls-hpke.test.ts`:
// differentially against `@hpke/core` itself (kept as a devDependency purely
// for this), and by RFC 9180's own test vectors for this suite. The RFC 9420
// vectors in `test/mls-vectors.test.ts` exercise it further, since Welcome and
// message protection are HPKE all the way down.
import { x25519 } from "@noble/curves/ed25519.js"
import { extract, expand } from "@noble/hashes/hkdf.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { gcm } from "@noble/ciphers/aes.js"
import { Hpke, HpkeAlgorithm, PrivateKey, PublicKey } from "../../hpke.js"
import { CryptoError } from "../../../mlsError.js"

// RFC 9180 §7: the registered ids for this suite.
const KEM_ID = 0x0020 // DHKEM(X25519, HKDF-SHA256)
const KDF_ID = 0x0001 // HKDF-SHA256
const AEAD_ID = 0x0001 // AES-128-GCM

const NSECRET = 32 // KEM shared secret
const NH = 32 // HKDF-SHA256 output
const NK = 16 // AES-128-GCM key
const NN = 12 // AES-128-GCM nonce
const NSK = 32 // X25519 private key
const NPK = 32 // X25519 public key

const HPKE_V1 = new TextEncoder().encode("HPKE-v1")

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

function i2osp2(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
}

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s)

/** `suite_id` for the KEM's own labeled KDF calls: "KEM" || I2OSP(kem_id, 2). */
const KEM_SUITE_ID = concat(ascii("KEM"), i2osp2(KEM_ID))
/** `suite_id` for the key schedule: "HPKE" || kem_id || kdf_id || aead_id. */
const HPKE_SUITE_ID = concat(ascii("HPKE"), i2osp2(KEM_ID), i2osp2(KDF_ID), i2osp2(AEAD_ID))

// RFC 9180 §4: LabeledExtract / LabeledExpand. The suite id is what keeps
// derivations from one HPKE suite from colliding with another's.
function labeledExtract(suiteId: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return extract(sha256, concat(HPKE_V1, suiteId, ascii(label), ikm), salt)
}

function labeledExpand(suiteId: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number): Uint8Array {
  return expand(sha256, prk, concat(i2osp2(length), HPKE_V1, suiteId, ascii(label), info), length)
}

const publicKeyOf = (bytes: Uint8Array): PublicKey => ({ bytes, keyType: "public" })
const privateKeyOf = (bytes: Uint8Array): PrivateKey => ({ bytes, keyType: "private" })

// RFC 9180 §4.1: ExtractAndExpand over the DH output, in the KEM's own suite.
function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const eaePrk = labeledExtract(KEM_SUITE_ID, new Uint8Array(), "eae_prk", dh)
  return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, NSECRET)
}

/** RFC 9180 §7.1.2 DHKEM(X25519) Encap. */
function encap(pkR: Uint8Array): { sharedSecret: Uint8Array; enc: Uint8Array } {
  const skE = x25519.utils.randomSecretKey()
  const pkE = x25519.getPublicKey(skE)
  const dh = x25519.getSharedSecret(skE, pkR)
  return { sharedSecret: extractAndExpand(dh, concat(pkE, pkR)), enc: pkE }
}

/** RFC 9180 §7.1.2 DHKEM(X25519) Decap. */
function decap(enc: Uint8Array, skR: Uint8Array): Uint8Array {
  const dh = x25519.getSharedSecret(skR, enc)
  return extractAndExpand(dh, concat(enc, x25519.getPublicKey(skR)))
}

interface Context {
  key: Uint8Array
  baseNonce: Uint8Array
  exporterSecret: Uint8Array
}

/** RFC 9180 §5.1 KeySchedule, base mode (mode 0x00, empty psk / psk_id). */
function keySchedule(sharedSecret: Uint8Array, info: Uint8Array): Context {
  const empty = new Uint8Array()
  const pskIdHash = labeledExtract(HPKE_SUITE_ID, empty, "psk_id_hash", empty)
  const infoHash = labeledExtract(HPKE_SUITE_ID, empty, "info_hash", info)
  const keyScheduleContext = concat(new Uint8Array([0x00]), pskIdHash, infoHash)
  const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", empty)
  return {
    key: labeledExpand(HPKE_SUITE_ID, secret, "key", keyScheduleContext, NK),
    baseNonce: labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", keyScheduleContext, NN),
    exporterSecret: labeledExpand(HPKE_SUITE_ID, secret, "exp", keyScheduleContext, NH),
  }
}

/** RFC 9180 §5.3 Secret Export. */
function exportSecretFrom(ctx: Context, exporterContext: Uint8Array, length: number): Uint8Array {
  return labeledExpand(HPKE_SUITE_ID, ctx.exporterSecret, "sec", exporterContext, length)
}

/** RFC 9180 §7.1.3 DeriveKeyPair for X25519. No clamping: X25519 clamps on
 * use, and the spec derives the scalar directly. */
function deriveKeyPairFrom(ikm: Uint8Array): { privateKey: PrivateKey; publicKey: PublicKey } {
  const dkpPrk = labeledExtract(KEM_SUITE_ID, new Uint8Array(), "dkp_prk", ikm)
  const sk = labeledExpand(KEM_SUITE_ID, dkpPrk, "sk", new Uint8Array(), NSK)
  return { privateKey: privateKeyOf(sk), publicKey: publicKeyOf(x25519.getPublicKey(sk)) }
}

export function makeHpke(_alg: HpkeAlgorithm): Hpke {
  return {
    async seal(publicKey, plaintext, info, aad) {
      const { sharedSecret, enc } = encap(publicKey.bytes)
      const ctx = keySchedule(sharedSecret, info)
      const ct = gcm(ctx.key, ctx.baseNonce, aad ?? new Uint8Array()).encrypt(plaintext)
      return { ct, enc }
    },
    async open(privateKey, kemOutput, ciphertext, info, aad) {
      try {
        const ctx = keySchedule(decap(kemOutput, privateKey.bytes), info)
        return gcm(ctx.key, ctx.baseNonce, aad ?? new Uint8Array()).decrypt(ciphertext)
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },
    async exportSecret(publicKey, exporterContext, length, info) {
      const { sharedSecret, enc } = encap(publicKey.bytes)
      return { enc, secret: exportSecretFrom(keySchedule(sharedSecret, info), exporterContext, length) }
    },
    async importSecret(privateKey, exporterContext, kemOutput, length, info) {
      try {
        return exportSecretFrom(keySchedule(decap(kemOutput, privateKey.bytes), info), exporterContext, length)
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },
    async importPrivateKey(k) {
      if (k.length !== NSK) throw new CryptoError(`HPKE private key must be ${NSK} bytes, got ${k.length}`)
      return privateKeyOf(k)
    },
    async importPublicKey(k) {
      if (k.length !== NPK) throw new CryptoError(`HPKE public key must be ${NPK} bytes, got ${k.length}`)
      return publicKeyOf(k)
    },
    async exportPublicKey(k) {
      return k.bytes
    },
    async exportPrivateKey(k) {
      return k.bytes
    },
    async encryptAead(key, nonce, aad, plaintext) {
      return gcm(key, nonce, aad ?? new Uint8Array()).encrypt(plaintext)
    },
    async decryptAead(key, nonce, aad, ciphertext) {
      try {
        return gcm(key, nonce, aad ?? new Uint8Array()).decrypt(ciphertext)
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },
    async deriveKeyPair(ikm) {
      return deriveKeyPairFrom(ikm)
    },
    async generateKeyPair() {
      const sk = x25519.utils.randomSecretKey()
      return { privateKey: privateKeyOf(sk), publicKey: publicKeyOf(x25519.getPublicKey(sk)) }
    },
    keyLength: NK,
    nonceLength: NN,
  }
}
