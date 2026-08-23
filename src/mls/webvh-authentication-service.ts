// The Authentication Service role (RFC 9750 §4): does an MLS leaf's
// credential really belong to the signature key in that leaf?
//
// The credential is a DID URL (`did#fragment`, mls/identity.ts). This
// resolves the DID and checks that its `verificationMethod` entry named by
// the fragment holds the SAME Ed25519 key MLS is asking us to authenticate —
// the actual binding RFC 9420's AS exists to prove, and stricter than the
// pre-rewrite implementation's check (`did document lists this kid` without
// confirming which key it names — src.bak/mls/authservice.ts, which checked
// keyAgreement list membership only). No new credential shape is needed:
// PLANMLSDIDCRED.md's `did_webvh_credential` design reduces to this once the
// existing `did#fragment` string is read as (did, verification_method_id)
// rather than invented as a separate wire format.
//
// Fail-closed, matching WebvhSigningKeyResolver's stance for the same
// reason: an AS that fails open on an unresolvable DID lets anyone add an
// unauthenticated leaf during a resolver hiccup, which is a strictly worse
// failure mode than briefly refusing a real member. Availability is a
// caching problem (PLAN.md tracks a resolver cache as a separate item), not
// a reason to accept an unverified leaf.
import { equalBytes } from '../protocol/canonical.ts'
import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { resolve } from '../identity/webvh/resolver.ts'
import { memberIdOf } from './identity.ts'
import type { AuthenticationService, Credential } from './vendor/index.ts'

export const webvhAuthenticationService: AuthenticationService = {
  async validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean> {
    let did: string
    let kid: string
    try {
      ;({ did, kid } = memberIdOf(credential))
    } catch {
      return false
    }
    let doc
    try {
      doc = await resolve(did)
    } catch {
      return false
    }
    if (!doc) return false
    const verificationMethod = doc.verificationMethod.find(entry => entry.id === kid)
    if (!verificationMethod) return false
    let documentPublicKey: Uint8Array
    try {
      documentPublicKey = decodeMultikey(verificationMethod.publicKeyMultibase)
    } catch {
      return false
    }
    return equalBytes(documentPublicKey, signaturePublicKey)
  },
}
