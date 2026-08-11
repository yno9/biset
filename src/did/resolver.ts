// Method dispatcher (DID.md: "resolve(did): Promise<DIDDocument> is the ONLY
// method abstraction — no other code may assume the method"). Still
// re-exports the did:dht implementation wholesale — its types/helpers
// (freshness, packet, etc.) remain load-bearing for the code that lazily
// dispatches to a pre-existing local did:dht record (didcomm-devices.ts's
// methodOpsFor) — but `resolveAny` below, the seam every NEW resolve should
// go through, no longer dispatches to it at all (2026-08-11: did:dht
// deprecated, see [[project_biset_did]]/PLANWEBVH.md). A did:dht string
// resolves to null here — fail-closed, same as any other unresolvable DID —
// rather than actually asking the DHT.
export * from './dht/resolver.ts'

import { resolve as resolveWebvh } from './webvh/resolver.ts'
import type { DidDocument } from './dht/document.ts'
import type { WebvhDidDocument } from './webvh/document.ts'

/** Resolves did:webvh; did:dht is sealed off (returns null unconditionally —
 * see file header). `gatewayUrls` is accepted for call-site compatibility
 * but unused now that the only live method (did:webvh) derives its own URL
 * from the DID string itself. */
export async function resolveAny(
  did: string, _gatewayUrls: string[] = [], _opts?: { skipCache?: boolean },
): Promise<DidDocument | WebvhDidDocument | null> {
  if (did.startsWith('did:webvh:')) return resolveWebvh(did)
  return null
}
