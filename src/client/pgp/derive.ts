// The identity's OpenPGP key, derived from the generation seed instead of made at random: every device computes the
// same key, so there is nothing to store, to sync or to race over, and a new generation (a device was removed) is a new key.
//
//   primary    Ed25519, the very key `#biset-generation` publishes in the DID document (rotation-key.ts), so the DID
//              document vouches for the PGP key's fingerprint. Used for nothing but DID Rotation and OpenPGP signatures.
//   encryption X25519, from the seed under its own label (an Ed25519 key cannot encrypt, and a signing key is not turned
//              into an encryption key).
//
// The format is the one Delta Chat uses: v4, EdDSA (legacy, algorithm 22) and ECDH on curve25519 (legacy, algorithm 18).
// The creation time and the time of the self-signatures are fixed, and the signatures are deterministic, so the
// certificate is the same bytes everywhere (the same idea as Autocrypt v2's fixed creation time).
import * as openpgp from 'openpgp'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { rotationSigningKey } from '../didcomm/rotation-key.ts'
import { describeKey, type PgpKey } from './keyring.ts'

/** Fixed, so the fingerprint and the signatures do not depend on when a device first derived the key. */
export const DERIVED_KEY_TIME = new Date('2026-06-30T23:59:59Z')

const ENCRYPTION_LABEL = 'biset/pgp/encryption/v1'

const DETERMINISTIC: openpgp.PartialConfig = { nonDeterministicSignaturesViaNotation: false }

/** The X25519 secret (little-endian, clamped as RFC 7748 asks) of the identity's encryption key for `seed`. */
function encryptionSecret(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new TypeError('generation seed must be 32 bytes')
  const secret = hkdf(sha256, seed, undefined, new TextEncoder().encode(ENCRYPTION_LABEL), 32)
  secret[0]! &= 248
  secret[31]! &= 127
  secret[31]! |= 64
  return secret
}

/** The key of generation seed `seed` for `address`. Same seed and address, same bytes. */
export async function derivePgpKey(seed: Uint8Array, address: string): Promise<PgpKey> {
  const signing = rotationSigningKey(seed)
  const secret = encryptionSecret(seed)
  // openpgp.js has no way to make a key from given secrets, so it makes a throwaway key (which also supplies the
  // algorithm parameters), the secrets are replaced, and the key is certified again, at the fixed time.
  const { privateKey: template } = await openpgp.generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ email: address }], date: DERIVED_KEY_TIME, format: 'object', config: DETERMINISTIC })
  const primary = template.keyPacket as unknown as KeyPacket
  const subkey = template.subkeys[0]!.keyPacket as unknown as KeyPacket
  primary.publicParams.Q = new Uint8Array([0x40, ...signing.publicKey])
  primary.privateParams!.seed = signing.privateKey
  subkey.publicParams.Q = new Uint8Array([0x40, ...x25519.getPublicKey(secret)])
  subkey.privateParams!.d = Uint8Array.from(secret).reverse() // OpenPGP keeps the scalar big-endian
  for (const packet of [primary, subkey]) { packet.created = DERIVED_KEY_TIME; await packet.computeFingerprintAndKeyID() }
  const key = await openpgp.reformatKey({ privateKey: template, userIDs: [{ email: address }], date: DERIVED_KEY_TIME, format: 'object', config: DETERMINISTIC })
  return describeKey(key.privateKey)
}

interface KeyPacket {
  created: Date
  computeFingerprintAndKeyID(): Promise<void>
  publicParams: { Q: Uint8Array }
  privateParams?: { seed?: Uint8Array; d?: Uint8Array }
}

/** Whether `publicKey` (Ed25519, 32 bytes) is the primary key of the PGP key derived for `seed`: the check a peer makes
 * against the DID document's `#biset-generation`. */
export function isPrimaryOf(seed: Uint8Array, publicKey: Uint8Array): boolean {
  const derived = ed25519.getPublicKey(rotationSigningKey(seed).privateKey)
  return derived.length === publicKey.length && derived.every((byte, index) => byte === publicKey[index])
}
