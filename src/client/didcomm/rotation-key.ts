// The key that signs this identity's DID Rotation (`from_prior`,
// PLAN-refactor.md §3-4): one Ed25519 key per relationship seed, derived from
// the seed, its public half published in the identity's DID document under a
// fixed id, referenced from `authentication` (where DIDComm v2.1 looks for a
// signing key). Whoever has the seed -- this identity's current devices, by
// Vault Sync -- can sign with it; replacing the seed (removing a device)
// replaces the published key in the same document edit, so a removed device's
// copy stops verifying.
//
// The published key is also the seed's authority: the seed in use is the one
// whose key the document lists (relationship-seed-bootstrap.ts).
import { ed25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { encodeMultikey } from '../../protocol/webvh/multikey.ts'
import { authenticationKeyOf } from '../../protocol/didcomm/from-prior.ts'

/** The rotation key's id in the DID document. Fixed, so that every device
 * asking for "the" rotation key asks for the same one (did.md's `ifAbsent`
 * keeps the first one approved). */
export const ROTATION_KEY_FRAGMENT = '#didcomm-rotation'

/** The Ed25519 signing key a 32-byte relationship seed stands for. Kept apart
 * from the seed's other use (relationship did:peers, peer.ts) by its own
 * derivation label. */
export function rotationSigningKey(seed: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array; publicKeyMultibase: string } {
  if (seed.length !== 32) throw new TypeError('relationship seed must be 32 bytes')
  const privateKey = hkdf(sha256, seed, undefined, new TextEncoder().encode('biset/did-rotation/signing/v1'), 32)
  const publicKey = ed25519.getPublicKey(privateKey)
  return { privateKey, publicKey, publicKeyMultibase: encodeMultikey(publicKey) }
}

/** The document-edit entry that publishes `seed`'s rotation key: `ifAbsent`
 * when any device may be the first to publish one (the first approved wins),
 * `replace` when the identity's seed is being replaced. */
export function rotationKeyEditMethod(seed: Uint8Array, mode: 'ifAbsent' | 'replace'): { id: string; type: 'Multikey'; controller: string; publicKeyMultibase: string; relationships: ['authentication']; mode: 'ifAbsent' | 'replace' } {
  return { id: ROTATION_KEY_FRAGMENT, type: 'Multikey', controller: '', publicKeyMultibase: rotationSigningKey(seed).publicKeyMultibase, relationships: ['authentication'], mode }
}

/** The rotation key a DID document publishes (its multibase), when it
 * publishes one: under ROTATION_KEY_FRAGMENT and referenced from
 * `authentication`. */
export function publishedRotationKey(document: Parameters<typeof authenticationKeyOf>[0]): string | undefined {
  return authenticationKeyOf(document, ROTATION_KEY_FRAGMENT)
}
