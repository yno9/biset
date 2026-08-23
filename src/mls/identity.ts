// What an MLS leaf claims to be, and how that claim maps onto a biset identity.
//
// MLS gives every leaf a Credential. RFC 9420 leaves its contents to the
// application, and PLANMLS.md §2 assigns the Authentication Service role to
// the DID layer — so the credential is nothing but a **DIDComm device key id**,
// the exact `did#kN` string `didcomm/register.ts` already mints and publishes
// in the identity's DID document:
//
//     did:webvh:example.com:alice#k1
//
// That form is deliberate:
//
//   - **One leaf per device**, not per identity. Every biset device already has
//     its own `_k1`, registers itself with the mediator and appears as its own
//     `keyAgreement` entry (ARC.md "Every device of an identity is a separate
//     DIDComm peer"). A group whose leaves were per-identity would have to
//     share MLS private state between devices — exactly the thing MLS's
//     forward secrecy is designed to make impossible.
//   - **Resolvable as-is.** The DID part names a document; the fragment names a
//     key inside it. Verifying a leaf is therefore "resolve the DID, check the
//     fragment is still listed" — no new registry, no new wire format
//     (Phase 2 / PLANMLS.md §4 "AS レイヤーの統合" builds on exactly this).
//   - **Revocation comes free.** A device removed from the DID document (see
//     `did/didcomm-devices.ts`) stops verifying, and its MLS leaf is then
//     removed by an ordinary Remove proposal.
//
// `credentialType: 'basic'` is the right container: the identity is an opaque
// byte string to MLS, and its meaning — "a DID URL, resolve it" — lives here.
import type { Credential } from './vendor/index.ts'

const enc = new TextEncoder()
const dec = new TextDecoder()

/** A DIDComm device key id: `<did>#<fragment>`, one per device. */
export interface MlsMemberId { did: string; kid: string }

/** The `did#kN` string as MLS sees it. */
export function credentialFor(kid: string): Credential {
  if (!kid.includes('#')) throw new Error(`credentialFor: not a DID URL with a key fragment: ${kid}`)
  return { credentialType: 'basic', identity: enc.encode(kid) }
}

/** Reads a leaf's credential back. Throws on anything that isn't ours —
 * an X.509 credential, or a basic one that isn't a `did#kN` DID URL, is not a
 * biset member and must not be silently treated as one. */
export function memberIdOf(credential: Credential): MlsMemberId {
  if (credential.credentialType !== 'basic') throw new Error(`memberIdOf: unsupported credential type ${credential.credentialType}`)
  const kid = dec.decode(credential.identity)
  const hash = kid.indexOf('#')
  if (!kid.startsWith('did:') || hash < 0) throw new Error(`memberIdOf: not a DID URL: ${kid}`)
  return { did: kid.slice(0, hash), kid }
}

/** The identity behind a device key id — `did:webvh:x#k1` → `did:webvh:x`. */
export function didOfKid(kid: string): string {
  const hash = kid.indexOf('#')
  return hash < 0 ? kid : kid.slice(0, hash)
}
