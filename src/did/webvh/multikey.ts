// Multikey (did:key-style multibase+multicodec public key encoding). Ed25519
// is the only key type did:webvh v1.0's eddsa-jcs-2022 cryptosuite uses for
// LOG SIGNING (DIDWEBVHFEAT.md §6), but a biset DID document's
// `verificationMethod` also carries X25519 keyAgreement keys — one per
// registered device, same concept as dht/document.ts's DidKeyAgreement, just
// encoded as multikey instead of raw DNS records. Both share this codec, the
// multicodec prefix is just a different 2 bytes.
//
// ML-KEM-768 (PLAN.md "did:webvh PQハイブリッド化") adds a third, longer key:
// the multicodec table's `mlkem-768-pub` entry (draft status, FIPS 203) is
// 0x120c, whose varint encoding is the 2 bytes below — same 2-byte shape as
// Ed25519/X25519 by coincidence of the codec's own numeric range, not because
// varints are always 2 bytes. Carried as its own verificationMethod entry
// (`#kk<n>`, webvh/document.ts) paired by slot number with the X25519 entry
// at `#k<n>` — not merged into one custom composite key, since multicodec has
// no registered code for an X25519+ML-KEM-768 composite and inventing one
// would make every entry unrecognizable to tooling that only knows the
// registered codes.
import { base58 } from '@scure/base'

const ED25519_PUB_MULTICODEC = [0xed, 0x01] as const // varint(0xed01), registered Ed25519-pub code
const X25519_PUB_MULTICODEC = [0xec, 0x01] as const // varint(0xec01), registered X25519-pub code
const MLKEM768_PUB_MULTICODEC = [0x8c, 0x24] as const // varint(0x120c), draft mlkem-768-pub code
const KEY_LEN = 32
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

export function encodeMultikey(ed25519PublicKey: Uint8Array): string {
  return encode(ed25519PublicKey, ED25519_PUB_MULTICODEC, KEY_LEN)
}

export function decodeMultikey(multikey: string): Uint8Array {
  return decode(multikey, ED25519_PUB_MULTICODEC, 'Ed25519', KEY_LEN)
}

export function encodeX25519Multikey(x25519PublicKey: Uint8Array): string {
  return encode(x25519PublicKey, X25519_PUB_MULTICODEC, KEY_LEN)
}

export function decodeX25519Multikey(multikey: string): Uint8Array {
  return decode(multikey, X25519_PUB_MULTICODEC, 'X25519', KEY_LEN)
}

export function encodeMlkem768Multikey(mlkem768PublicKey: Uint8Array): string {
  return encode(mlkem768PublicKey, MLKEM768_PUB_MULTICODEC, MLKEM768_KEY_LEN)
}

export function decodeMlkem768Multikey(multikey: string): Uint8Array {
  return decode(multikey, MLKEM768_PUB_MULTICODEC, 'ML-KEM-768', MLKEM768_KEY_LEN)
}
