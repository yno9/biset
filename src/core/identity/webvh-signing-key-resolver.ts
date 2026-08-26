import { decodeMultikey } from '../../identity/webvh/multikey.ts'
import { resolve } from '../../identity/webvh/resolver.ts'
import type { DeviceSigningPublicKeyResolver } from './ed25519-device-control-verifier.ts'

/**
 * The Authentication Service role (RFC 9750 §4, `PLANMLSARCH.md` §3): resolves
 * a device's signing key id (`did:webvh:...#fragment`) to its Ed25519 public
 * key by fetching and verifying the DID's did:webvh log, then matching by
 * FRAGMENT — not by the full kid string. Unlike MLS credential validation
 * elsewhere in the codebase, this resolver is fail-closed — a DID that cannot
 * be resolved, or a fragment absent from its verificationMethod, yields
 * `undefined`, and the caller's signature check then fails. This resolver
 * backs device-control signature verification (roster ACK/pull/append/restore
 * control) and the MLS DS's own control-plane signatures
 * (`mls-delivery-authorizer.ts`), where accepting an unverifiable key would
 * defeat the check it is used for.
 *
 * Fragment matching, not full-string matching, is the root fix for a domain
 * move (identity/webvh/move.ts): `migrateWebvhLocation`'s whole-document
 * string substitution rewrites the did PREFIX of every verificationMethod id
 * in the document — the mover's and every OTHER device's alike — but never
 * touches the `#fragment` suffix, which is what actually names one device
 * across the identity's whole lifetime. `resolve(did)` already re-verifies
 * the ENTIRE hash-chained, signed log from genesis before returning a
 * document (`resolveEntries`), so a document returned for an old, pre-move
 * `did` is confirmed to be the SAME SCID's own current, legitimate
 * continuation — matching one of its entries by `${doc.id}#${fragment}`
 * (the CURRENT id plus the caller's original fragment) instead of by
 * `signingKeyId` verbatim trusts nothing beyond what full-string matching
 * already trusted; it just stops conflating "current" with "still prefixed
 * the same way it was when this kid was first handed out." A device that
 * never moved keeps resolving through any move a SIBLING device makes,
 * without needing to know the move happened at all, and a device contacting
 * a given resolver for the very first time works identically whether or not
 * the identity has already moved since its kid was minted.
 *
 * On top of that, a small in-memory cache pins successfully resolved
 * `(kid, key)` pairs for the resolver's lifetime — a signing key id is never
 * legitimately rebound to a different key (a replaced device credential gets
 * a new fragment, not a reused one), so this is a safe performance/
 * resilience layer, not a correctness shortcut: it also keeps a kid
 * verifiable across a transient failure to reach the DID's host at all,
 * which fragment matching alone cannot help with (there is no document to
 * search fragments in if resolution itself fails). Revocation/membership is
 * enforced separately (roster membership checks, `didOfKid` checks) — this
 * resolver only ever answers "did this kid's owner sign this."
 */
export class WebvhSigningKeyResolver implements DeviceSigningPublicKeyResolver {
  private readonly cache = new Map<string, Uint8Array>()

  async resolveEd25519PublicKey(signingKeyId: string): Promise<Uint8Array | undefined> {
    const cached = this.cache.get(signingKeyId)
    if (cached) return cached

    const hash = signingKeyId.indexOf('#')
    if (hash < 0) return undefined
    const did = signingKeyId.slice(0, hash)
    const fragment = signingKeyId.slice(hash)
    let doc
    try {
      doc = await resolve(did)
    } catch {
      return undefined
    }
    if (!doc) return undefined
    const vm = doc.verificationMethod.find(entry => entry.id === `${doc.id}${fragment}`)
    if (!vm) return undefined
    let publicKey: Uint8Array
    try {
      publicKey = decodeMultikey(vm.publicKeyMultibase)
    } catch {
      return undefined
    }
    this.cache.set(signingKeyId, publicKey)
    return publicKey
  }
}
