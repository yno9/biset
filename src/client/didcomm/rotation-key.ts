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

/** The id of biset's own key in the DID document: the one general-purpose key biset has there (it signs the DID
 * Rotation, and is what the relationship seed is known by). Fixed, so that every device asking for "the" key asks
 * for the same one (did.md's `ifAbsent` keeps the first one approved). It is not `#didcomm`, the service's id: a
 * document's ids are one namespace (a `remove` of `#didcomm` would take both). */
export const ROTATION_KEY_FRAGMENT = '#biset'

/** What the key was called before. A document published then keeps it until the key is renewed (and then loses it). */
export const LEGACY_ROTATION_KEY_FRAGMENT = '#didcomm-rotation'

/** The ids a document may publish the key under; the old one first, so a document that still has it keeps
 * it as the authority (a new device's `ifAbsent` for the new id must not take over from it). */
const ROTATION_KEY_FRAGMENTS = [LEGACY_ROTATION_KEY_FRAGMENT, ROTATION_KEY_FRAGMENT] as const

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

/** The id and key (multibase) a DID document publishes the rotation key under, when it publishes one: referenced from
 * `authentication`. */
export function publishedRotation(document: Parameters<typeof authenticationKeyOf>[0]): { fragment: string; key: string } | undefined {
  for (const fragment of ROTATION_KEY_FRAGMENTS) {
    const key = authenticationKeyOf(document, fragment)
    if (key) return { fragment, key }
  }
  return undefined
}

/** The rotation key a DID document publishes (its multibase), when it publishes one. */
export function publishedRotationKey(document: Parameters<typeof authenticationKeyOf>[0]): string | undefined {
  return publishedRotation(document)?.key
}

/** The ids a log may have published the key under, in the order they are looked for (relationship-seed-bootstrap.ts). */
export const rotationKeyFragments: readonly string[] = ROTATION_KEY_FRAGMENTS
