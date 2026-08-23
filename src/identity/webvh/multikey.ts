// Multikey (did:key-style multibase+multicodec public key encoding), Ed25519
// only — the only key type did:webvh v1.0's eddsa-jcs-2022 cryptosuite uses
// for LOG SIGNING, and the only key type this resolver needs (device
// keyAgreement/ML-KEM entries belong to the DIDComm transport layer, not the
// signing-key resolution this module exists for).
import { base58 } from '@scure/base'

const ED25519_PUB_MULTICODEC = [0xed, 0x01] as const // varint(0xed01), registered Ed25519-pub code
const KEY_LEN = 32

export function decodeMultikey(multikey: string): Uint8Array {
  if (!multikey.startsWith('z')) throw new Error('decodeMultikey: expected multibase base58btc ("z"-prefixed)')
  const bytes = base58.decode(multikey.slice(1))
  if (bytes.length !== 2 + KEY_LEN) throw new Error('decodeMultikey: unexpected length')
  if (bytes[0] !== ED25519_PUB_MULTICODEC[0] || bytes[1] !== ED25519_PUB_MULTICODEC[1]) {
    throw new Error('decodeMultikey: not an Ed25519 multicodec key')
  }
  return bytes.slice(2)
}
