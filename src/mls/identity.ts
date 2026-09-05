// What an MLS leaf claims to be, and how that claim maps onto a biset identity.
//
// MLS gives every leaf a Credential. RFC 9420 leaves its contents to the
// application. Biset uses a generation-bound device credential containing the
// stable identity id, a derived device id, and that leaf's Ed25519 public key.
// The device key is deliberately not published in the DID document:
//
//   - **One leaf per device**, not per identity. Every biset device already has
//     its own leaf. A group whose leaves were per-identity would have to
//     share MLS private state between devices — exactly the thing MLS's
//     forward secrecy is designed to make impossible.
//   - **Root-authorized.** Validation resolves only `${did}#key-1`, verifies
//     the embedded Root signature, then checks the embedded key against the
//     actual MLS leaf key.
//   - **Self Group is the roster.** Revocation is an MLS Remove; DID document
//     mutation is neither required nor authoritative.
//
// `credentialType: 'basic'` is the right container: MLS transports the
// canonical credential bytes while biset's Authentication Service interprets
// and validates them.
import type { Credential } from '../vendor/mls/credential.ts'
import { credentialForMlsDevice, mlsDeviceCredentialOf, type MlsDeviceCredentialV2 } from './device-credential.ts'

/** An MLS device identity, one leaf per device. */
export interface MlsMemberId { did: string; kid: string }

/** The generation-bound device credential as MLS sees it. */
export function credentialFor(value: MlsDeviceCredentialV2): Credential {
  return credentialForMlsDevice(value)
}

/** Reads a leaf's credential back. Throws on anything that isn't ours —
 * an X.509 credential, or a BasicCredential not encoded by biset, is not a
 * biset member and must not be silently treated as one. */
export function memberIdOf(credential: Credential): MlsMemberId {
  const value = mlsDeviceCredentialOf(credential)
  return { did: value.identityId, kid: value.deviceKid }
}
