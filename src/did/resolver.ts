// Method dispatcher (DID.md: "resolve(did): Promise<DIDDocument> is the ONLY
// method abstraction — no other code may assume the method").
//
// did:webvh is the only method, so this file is one branch and a fallthrough.
// It stays a dispatcher anyway: it is the seam a second method would be added
// at, and did:dht proved that seam earlier — the capability was the point,
// not the method (ARC.md). Every unknown DID resolves to null, fail-closed.
import { resolve as resolveWebvh } from './webvh/resolver.ts'
import type { WebvhDidDocument } from './webvh/document.ts'

/** Resolves did:webvh. `gatewayUrls`/`opts` are accepted for call-site
 * compatibility but unused — the only live method derives its own URL from
 * the DID string itself. */
export async function resolveAny(
  did: string, _gatewayUrls: string[] = [], _opts?: { skipCache?: boolean },
): Promise<WebvhDidDocument | null> {
  if (did.startsWith('did:webvh:')) return resolveWebvh(did)
  return null
}
