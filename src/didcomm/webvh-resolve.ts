// Splices routing.json's keyAgreement/service into a document resolved from
// the signed did:webvh log alone — identity/webvh/resolver.ts's own resolve()
// deliberately returns an empty `service`/no `keyAgreement` (that module's
// header: "wrong for anything that needs DIDComm routing data"). This is the
// DIDComm-side counterpart that actually needs it, kept out of resolver.ts
// itself so the core identity resolver stays free of DIDComm concerns.
//
// Ported from src.bak/did/webvh/resolver.ts's mergeRouting.
import { resolve } from '../identity/webvh/resolver.ts'
import type { WebvhDidDocument } from '../identity/webvh/document.ts'
import { defaultFetch } from '../net-fetch.ts'
import { fetchRouting, type RoutingDoc } from './webvh-routing.ts'
import { decodeX25519Multikey } from './multikey.ts'
import { didOfKid } from '../shared/protocol/ids.ts'

/** `routing === null` means "no routing.json exists for this identity" —
 * this identity simply hasn't provisioned a DIDComm-capable device yet.
 * Returns `doc` untouched in that case (nothing to add). */
function mergeRouting(doc: WebvhDidDocument, routing: RoutingDoc | null): WebvhDidDocument {
  if (!routing) return doc
  const kaVms = routing.keyAgreementVerificationMethod ?? []
  const mlkemVms = routing.mlkemVerificationMethod ?? []
  return {
    ...doc,
    verificationMethod: [...doc.verificationMethod, ...kaVms, ...mlkemVms],
    ...(kaVms.length ? { keyAgreement: kaVms.map(vm => vm.id) } : {}),
    // Concatenated, not replaced: `doc.service` from the signed log is just
    // the one constant `#routing` pointer entry (webvh-routing-pointer.ts) —
    // routing.json's own entries add to it rather than overwriting it, so
    // that pointer survives every resolve instead of being wiped out by the
    // same merge that's supposed to be adding MORE service info.
    service: [...doc.service, ...routing.service],
    // resolver.ts's own resolve() always returns `alsoKnownAs: []` (the
    // signed log never carries it) -- routing.json is the only place it's
    // ever actually written (identity/bootstrap.ts's enableDidComm), so
    // there's nothing from `doc` to concatenate here, only replace.
    ...(routing.alsoKnownAs?.length ? { alsoKnownAs: routing.alsoKnownAs } : {}),
    ...(routing.name ? { name: routing.name } : {}),
  }
}

/** resolve() (the signed log alone) + routing.json, merged. What a DIDComm
 * sender actually needs: a keyAgreement key and a DIDCommMessaging service
 * endpoint to address this identity.
 *
 * Fetches routing.json from `doc.id` (the FRESHLY resolved, current did),
 * not the caller's possibly-stale `did` argument. Unlike did.jsonl, a
 * domain move's `identity/webvh/move.ts` carries routing.json to the NEW
 * location only -- there is no old-location dual-write for it the way
 * `migrateWebvhLocation` does for the signed log -- so the old location's
 * routing.json is simply never updated after a move and stays frozen at
 * whatever it said before. Fetching it via `did` (old-prefixed, if that's
 * what the caller passed) would silently serve that stale copy forever;
 * `doc.id` is already known-current at this point because `resolve()`
 * just re-verified the entire hash-chained did.jsonl log to produce it. */
export async function resolveWithRouting(did: string, fetchImpl: typeof fetch = defaultFetch()): Promise<WebvhDidDocument | null> {
  const doc = await resolve(did)
  if (!doc) return null
  const routing = await fetchRouting(doc.id, fetchImpl)
  return mergeRouting(doc, routing)
}

/** Resolves a DIDComm sender's kid (a full DID URL, `did:webvh:...#k_<hash>`)
 * to its published X25519 keyAgreement public key -- crypto.ts's
 * `ResolveSenderKey`, backed by a live resolve+routing.json fetch. Throws if
 * the identity doesn't resolve, or hasn't published a keyAgreement entry
 * for this exact kid (a JWE claiming a sender that never registered this
 * key cannot be authenticated, so there is nothing safe to decrypt with).
 *
 * Matches by `#fragment` against the resolved document's OWN current id,
 * not `senderKid` verbatim -- same fix, same reason, as
 * core/identity/webvh-signing-key-resolver.ts's own header: a did:webvh
 * domain move rewrites every verificationMethod's did PREFIX at once
 * (routing.json's keyAgreement entries included -- identity/webvh/move.ts's
 * own afterNewLocationWritten hook carries it over the same way), but never
 * the `#fragment` suffix. A sender whose OWN didCommKid was never re-issued
 * (any device other than the one that performed the move) would otherwise
 * become permanently unauthenticatable the instant a SIBLING device moves. */
export async function resolveDidCommSenderKey(senderKid: string, fetchImpl: typeof fetch = defaultFetch()): Promise<Uint8Array> {
  const hash = senderKid.indexOf('#')
  if (hash < 0) throw new Error(`resolveDidCommSenderKey: not a DID URL: ${senderKid}`)
  const did = didOfKid(senderKid)
  const fragment = senderKid.slice(hash)
  const doc = await resolveWithRouting(did, fetchImpl)
  if (!doc) throw new Error(`resolveDidCommSenderKey: sender identity ${did} does not resolve`)
  const vm = doc.verificationMethod.find(v => v.id === `${doc.id}${fragment}`)
  if (!vm) throw new Error(`resolveDidCommSenderKey: ${senderKid} is not a published keyAgreement entry`)
  return decodeX25519Multikey(vm.publicKeyMultibase)
}
