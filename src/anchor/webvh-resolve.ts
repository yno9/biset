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
import { resolveEntries, mergeRouting } from '../did/webvh/resolver.ts'
import type { WebvhDidDocument } from '../did/webvh/document.ts'
import { didToRoutingUrl, type RoutingDoc } from '../did/webvh/routing.ts'
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

/** Whether this store holds ANY did.jsonl for `did`'s path at all —
 * independent of what it resolves to. The one thing `resolveOwnWebvhDocument`
 * alone can't tell a caller: its `null` already means both "nothing here"
 * and "something here, resolved to nothing" (deactivated), and
 * `resolveWebvhDocument` needs to tell those apart to know whether a remote
 * fallback is warranted at all. */
function storedLocally(webvh: WebvhLogStore, did: string): boolean {
  try {
    const parts = parseWebvhDid(did)
    if (parts.pathSegments.length !== 1 || !parts.pathSegments[0]) return false
    return webvh.read(parts.domain, parts.pathSegments[0]) !== null
  } catch { return false }
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
  if (webvh && storedLocally(webvh, did)) {
    // Present in this anchor's own store — trust that answer outright,
    // INCLUDING a `null` one (a deactivated identity, resolveEntries's own
    // documented return). `resolveOwnWebvhDocument`'s `null` is otherwise
    // ambiguous between "resolved to nothing" and "nothing stored here at
    // all" — `storedLocally` above is what disambiguates them, so this
    // branch is only reached for the former. Skipping the remote fallback
    // here isn't just an optimization: a deactivated identity's OWN former
    // did.jsonl already answers this correctly, and needlessly re-asking a
    // domain this anchor doesn't control for permission to trust its own
    // data is exactly backwards.
    return resolveOwnWebvhDocument(webvh, did)
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

/** resolveWebvhDocument, plus routing.json's keyAgreement/service/name
 * (webvh/routing.ts's own note: none of that lives in the signed log any
 * more). Only the mediator's own key resolver (anchor/index.ts's
 * resolveDidWebvh) needs this — didbind.ts's root-key verification reads
 * only `authentication`/verificationMethod[0], which stay in the signed
 * document, so it keeps using resolveOwnWebvhDocument alone rather than
 * paying for a routing.json read it has no use for. Own-store-then-guarded-
 * remote, same fallback shape as resolveWebvhDocument itself; a missing or
 * unreachable routing.json degrades to "no extra info" (mergeRouting's own
 * fail-soft stance), not a resolution failure. */
export async function resolveWebvhDocumentWithRouting(did: string, webvh?: WebvhLogStore): Promise<WebvhDidDocument | null> {
  const doc = await resolveWebvhDocument(did, webvh)
  if (!doc) return null

  let routing: RoutingDoc | null = null
  if (webvh) {
    try {
      const parts = parseWebvhDid(doc.id)
      const json = parts.pathSegments.length === 1 && parts.pathSegments[0]
        ? webvh.readRouting(parts.domain, parts.pathSegments[0])
        : null
      routing = json ? (JSON.parse(json) as RoutingDoc) : null
    } catch { routing = null }
  }
  if (!routing) {
    try {
      routing = JSON.parse(await fetchGuarded(didToRoutingUrl(doc.id))) as RoutingDoc
    } catch { routing = null }
  }
  return mergeRouting(doc, routing)
}
