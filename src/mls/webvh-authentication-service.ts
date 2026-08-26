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
// Matches by `#fragment` against the resolved document's OWN current id
// (`${doc.id}${fragment}`), not by the credential's `kid` verbatim — same
// fix, same reason, as `core/identity/webvh-signing-key-resolver.ts`'s own
// header: a did:webvh domain move (identity/webvh/move.ts) rewrites every
// verificationMethod's did PREFIX at once, but never the `#fragment` suffix,
// so a device whose OWN credential was never re-issued (any device other
// than the one that performed the move) would otherwise stop validating the
// instant a SIBLING device moves. This matters here specifically because the
// vendored MLS library's `validateRatchetTree` (vendor/clientState.ts)
// re-validates EVERY leaf's credential — not just a changed one — whenever a
// device joins externally or processes a Welcome; a still-unmoved device's
// long-stale credential would otherwise fail that whole-tree check the
// moment ANY new device tries to join after ANY other device has moved.
// `resolve(did)` already re-verifies the entire hash-chained, signed log
// from genesis before returning a document, so this is not a new trust
// assumption — it stops conflating "current" with "still prefixed the way
// it was when this credential was minted," same as the resolver.
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
    const hash = kid.indexOf('#')
    if (hash < 0) return false
    const fragment = kid.slice(hash)
    let doc
    try {
      doc = await resolve(did)
    } catch {
      return false
    }
    if (!doc) return false
    const verificationMethod = doc.verificationMethod.find(entry => entry.id === `${doc.id}${fragment}`)
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
