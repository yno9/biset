// Resolves a did:webvh identifier against this anchor's OWN log store — no
// HTTP round trip back to itself, just the same verification resolve() uses
// for a real fetch (webvh/resolver.ts's resolveEntries). Shared by the two
// anchor-side jobs that need a document behind a did:webvh DID this anchor
// itself hosts: the mediator's peer-key lookup (index.ts's resolveDidWebvh)
// and the DID.md binding-proof verifier (didbind.ts's root-key resolver).
import type { WebvhLogStore } from './webvh-store.ts'
import { parseWebvhDid } from '../did/webvh/identifier.ts'
import { parseLog } from '../did/webvh/log.ts'
import { resolveEntries } from '../did/webvh/resolver.ts'
import type { WebvhDidDocument } from '../did/webvh/document.ts'

export function resolveOwnWebvhDocument(webvh: WebvhLogStore, did: string): WebvhDidDocument | null {
  try {
    const parts = parseWebvhDid(did)
    // biset's path-segment scheme (PLANWEBVH.md §2.3, no `dids/` prefix any
    // more — 2026-08-11): did:webvh:{scid}:{domain}:{username}
    if (parts.pathSegments.length !== 1 || !parts.pathSegments[0]) return null
    const jsonl = webvh.read(parts.domain, parts.pathSegments[0])
    if (!jsonl) return null
    return resolveEntries(did, parseLog(jsonl))
  } catch { return null }
}
