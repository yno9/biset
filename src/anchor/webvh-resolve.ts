// Resolves a did:webvh identifier — this anchor's OWN log store on a hit (no
// HTTP round trip back to itself), a guarded remote HTTPS fetch on a miss.
//
// The two used to be separate functions (`resolveOwnWebvhDocument`, own-store
// only) because nothing needed the other case: every DID this anchor was
// asked about was one it hosted itself. `authorized_did_domain`
// (jmapsmtp's ARC.md §2a) changes that — a mail domain can now name a
// did-domain THIS anchor does not host, and provisioning has to resolve it
// anyway. One function with a local-then-remote fallback, rather than two
// call sites each deciding which to use, is what keeps that fallback from
// being implemented once and forgotten at the other site.
//
// Same verification either way (`resolveEntries`, shared with the client's
// own `resolve()`): a log fetched from a stranger's domain gets exactly the
// same SCID/entryHash/proof checks a log from this anchor's own store does.
// The remote fetch goes through `ssrf-guard.ts` — unlike the browser's own
// resolve(), this runs in a server process an operator-supplied domain name
// (or a hostile CNAME) could otherwise point at internal infrastructure.
import type { WebvhLogStore } from './webvh-store.ts'
import { parseWebvhDid, didToHttpsUrl } from '../did/webvh/identifier.ts'
import { parseLog } from '../did/webvh/log.ts'
import { resolveEntries } from '../did/webvh/resolver.ts'
import type { WebvhDidDocument } from '../did/webvh/document.ts'
import { fetchGuarded, NotFoundError } from './ssrf-guard.ts'

/** Local-store-only resolve, kept as its own export for the one caller that
 * must never make a network call — didbind.ts's binding-proof verifier runs
 * against a DID this anchor's own account-creation flow JUST wrote, so a
 * remote fetch there would only ever be this anchor asking itself over HTTPS
 * for no reason. */
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

/** Resolves any did:webvh identifier: this anchor's own store first (cheap,
 * no network, and the freshest possible source for a log this same anchor
 * just accepted a write for), a guarded remote fetch on a miss — the
 * `authorized_did_domain` case, a did-domain this anchor does not host.
 * `webvh` is optional the same way it is everywhere else in this file (an
 * anchor instance with no webvh store configured just always falls through
 * to remote). Returns null for "no such DID" (own-store miss AND a remote
 * 404), throws for a genuine failure (SSRF-blocked, network error, bad log)
 * so a caller can tell "this identity doesn't exist" from "couldn't check". */
export async function resolveWebvhDocument(did: string, webvh?: WebvhLogStore): Promise<WebvhDidDocument | null> {
  if (webvh) {
    const own = resolveOwnWebvhDocument(webvh, did)
    if (own) return own
  }
  const url = didToHttpsUrl(did)
  let text: string
  try {
    text = await fetchGuarded(url)
  } catch (e) {
    if (e instanceof NotFoundError) return null
    throw e
  }
  return resolveEntries(did, parseLog(text))
}
