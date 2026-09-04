// The stable internal identity key (PLANWEBVH.md §3.1) — biset's SECOND thin
// method abstraction, alongside `resolve(did)`.
//
// Why this exists: a DID string is not uniformly stable. did:webvh's is
// `did:webvh:{SCID}:{domain}:{username}`, where only the SCID is
// self-certifying: a domain move (identity/webvh/publish.ts's own genesis
// log) keeps the SCID and the log, but the DID STRING changes. Keying
// biset's internal data model on the full string therefore breaks every
// contact, key-agreement and message association on a move.
//
// The normalization below keeps exactly the self-certifying part — the part
// derived from keys or from the genesis event, never from where the document
// happens to be hosted. Adding a method later means adding one branch here,
// nothing else.
//
// STRICTLY INTERNAL. Everything on the wire keeps using the full DID string:
// DIDComm `from`/`to`, mediator keylist kids (`{did}#k1`), DID document `id`
// and verificationMethod ids. No other implementation knows (or could know)
// about this representation, so it must never leave the client. That is also
// why the reverse direction matters: a stable key alone cannot address
// anything, so whatever holds one must also keep the current DID string
// alongside it (identity/record-store.ts's IdentityRecord.did).
import { parseWebvhDid } from './webvh/identifier.ts'

/** Normalizes an identity string (a DID, or a plain email for a DID-less
 * relay) to the key biset indexes it under internally. Total and lossless for
 * anything it doesn't recognize: an email or a malformed did:webvh both come
 * back unchanged, so callers can pass whatever identifier they hold without
 * pre-checking what it is. */
function stableIdKey(id: string): string {
  if (!id.startsWith('did:webvh:')) return id
  try {
    return `webvh:${parseWebvhDid(id).scid}`
  } catch {
    // Not parseable as did:webvh — leave it alone rather than inventing a key.
    // A caller comparing two such strings still gets correct equality; it just
    // gets no move-tolerance, which is the honest answer for an identifier
    // this module cannot interpret.
    return id
  }
}

/** True when `key` identifies a DID-rooted identity rather than a bare email
 * address. Callers used to test `startsWith('did:')` directly, which silently
 * became wrong once webvh identities normalize to a `webvh:` key — this is
 * the one place that knows every shape stableIdKey can produce. */
function isDidIdentityKey(key: string): boolean {
  return key.startsWith('did:') || key.startsWith('webvh:')
}

/** True when the two identifiers name the same identity, tolerating a
 * did:webvh domain move between them. Prefer this over `===` anywhere two
 * identity strings are compared for "is this me" / "is this the same
 * correspondent". */
export function sameIdentity(a: string, b: string): boolean {
  return a === b || stableIdKey(a) === stableIdKey(b)
}
