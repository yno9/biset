// The stable internal identity key -- comail's SECOND thin method abstraction,
// alongside `resolveDidDocument(did)`.
//
// A did:vh DID is `did:vh:{SCID}` and nothing else: it names no host, so moving the
// log to another place does not change it, and the SCID (derived from the genesis
// entry, never from where the document happens to be hosted) is the whole identity.
// What can differ between two strings for the same identity is only a DID URL
// fragment (`#k1`), so that is all the normalization strips.
//
// STRICTLY INTERNAL. Everything on the wire keeps using the full DID string:
// DIDComm `from`/`to`, mediator recipient DIDs and kids (`{did}#k1`), DID document `id`
// and verificationMethod ids. This representation never leaves the client.
import { vhScidOf } from '../../protocol/vh/identifier.ts'

/** Normalizes an identity string (a DID, or a plain email for a DID-less
 * relay) to the key comail indexes it under internally. Total and lossless for
 * anything it doesn't recognize: an email or a malformed did:vh both come
 * back unchanged, so callers can pass whatever identifier they hold without
 * pre-checking what it is. */
function stableIdKey(id: string): string {
  const scid = vhScidOf(id)
  return scid ? `vh:${scid}` : id
}

/** True when the two identifiers name the same identity, whatever DID URL
 * fragment each carries. Prefer this over `===` anywhere two identity
 * strings are compared for "is this me" / "is this the same correspondent". */
export function sameIdentity(a: string, b: string): boolean {
  return a === b || stableIdKey(a) === stableIdKey(b)
}
