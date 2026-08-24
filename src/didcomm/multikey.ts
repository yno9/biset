// Multikey (did:key-style multibase+multicodec public key encoding) for the
// two key types a DIDComm keyAgreement entry needs. Kept out of
// identity/webvh/multikey.ts deliberately — that module's own header:
// "device keyAgreement/ML-KEM entries belong to the DIDComm transport layer,
// not the signing-key resolution this module exists for" — Ed25519 (log
// signing) and these two (transport encryption) are different concerns.
//
// Ported from src.bak/did/webvh/multikey.ts's X25519/ML-KEM-768 halves.
import { base58 } from '@scure/base'

const X25519_PUB_MULTICODEC = [0xec, 0x01] as const // varint(0xec01), registered X25519-pub code
const MLKEM768_PUB_MULTICODEC = [0x8c, 0x24] as const // varint(0x120c), draft mlkem-768-pub code
const X25519_KEY_LEN = 32
const MLKEM768_KEY_LEN = 1184

function encode(publicKey: Uint8Array, codec: readonly [number, number], keyLen: number): string {
  if (publicKey.length !== keyLen) throw new Error(`encodeMultikey: expected ${keyLen}-byte public key`)
  const prefixed = new Uint8Array(2 + keyLen)
  prefixed[0] = codec[0]
  prefixed[1] = codec[1]
  prefixed.set(publicKey, 2)
  return 'z' + base58.encode(prefixed)
}

function decode(multikey: string, codec: readonly [number, number], label: string, keyLen: number): Uint8Array {
  if (!multikey.startsWith('z')) throw new Error('decodeMultikey: expected multibase base58btc ("z"-prefixed)')
  const bytes = base58.decode(multikey.slice(1))
  if (bytes.length !== 2 + keyLen) throw new Error('decodeMultikey: unexpected length')
  if (bytes[0] !== codec[0] || bytes[1] !== codec[1]) throw new Error(`decodeMultikey: not a ${label} multicodec key`)
  return bytes.slice(2)
}

export function encodeX25519Multikey(x25519PublicKey: Uint8Array): string {
  return encode(x25519PublicKey, X25519_PUB_MULTICODEC, X25519_KEY_LEN)
}

export function decodeX25519Multikey(multikey: string): Uint8Array {
  return decode(multikey, X25519_PUB_MULTICODEC, 'X25519', X25519_KEY_LEN)
}

export function encodeMlkem768Multikey(mlkem768PublicKey: Uint8Array): string {
  return encode(mlkem768PublicKey, MLKEM768_PUB_MULTICODEC, MLKEM768_KEY_LEN)
}

export function decodeMlkem768Multikey(multikey: string): Uint8Array {
  return decode(multikey, MLKEM768_PUB_MULTICODEC, 'ML-KEM-768', MLKEM768_KEY_LEN)
}
