// did:dht-specific key derivation: the identifier itself (didFromRootPublicKey)
// and its BEP44 continuation-record keys. Split out of ../keys.ts so that file
// stays method-agnostic (src/did/README-ish split: dht/ vs webvh/ vs peer/).
import { ed25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { KeyPair } from '../keys.ts'
import { zbase32Encode } from './zbase32.ts'

// Continuation records (resolver.ts's chaining): a BEP44 value is capped at
// 1000 bytes, so an identity with more relays than fit spills into further
// did:dht records, each its own DID naming its own key. Those keys are
// derived from the ROOT PRIVATE key rather than the master seed, so that
// publishDocument (which only ever holds rootPrivateKey — see store.ts: the
// seed is never persisted) can mint them without the seed travelling further
// into the codebase. Still fully seed-restorable: rootPrivateKey itself comes
// from the seed, so the 24 words rebuild the whole chain.
//
// Not a SLIP-0010 path because there is no seed here to walk one from; HKDF
// over the root private key with a domain-separating info string is the
// standard construction for exactly this ("give me an unlimited, indexed
// family of independent keys from one secret").
export function deriveContinuationKey(rootPrivateKey: Uint8Array, index: number): KeyPair {
  const info = new TextEncoder().encode(`biset did:dht continuation ${index}`)
  const key = hkdf(sha256, rootPrivateKey, undefined, info, 32)
  return { privateKey: key, publicKey: ed25519.getPublicKey(key) }
}

export function didFromRootPublicKey(rootPublicKey: Uint8Array): string {
  return `did:dht:${zbase32Encode(rootPublicKey)}`
}
