// The DIDComm side of did:webvh resolution: one sender-key resolver.
//
// Until 2026-09-16 this module also held `mergeRouting`/`resolveWithRouting`,
// which spliced routing.json's keyAgreement/service into the document
// resolved from the signed log. routing.json is retired: did.md publishes
// `keyAgreement` and the `#didcomm` service INTO the signed log (verified
// live against `cb81.did.md/.well-known/did.jsonl`), so `resolve()` alone
// already returns everything a DIDComm sender needs. Callers that wanted a
// route now call webvh-route.ts's `didCommRouteFromDocument` on that
// document.
import { resolve } from '../webvh/resolver.ts'
import { defaultFetch } from '../net-fetch.ts'
import { decodeX25519Multikey } from './multikey.ts'
import { didOfKid } from '../ids.ts'
import { resolveDidWeb } from './did-web.ts'

/** Resolves a DIDComm sender's kid (a full DID URL, `did:webvh:...#k_<hash>`)
 * to its published X25519 keyAgreement public key -- crypto.ts's
 * `ResolveSenderKey`, backed by a live resolve. Throws if the identity
 * doesn't resolve, or hasn't published a keyAgreement entry for this exact
 * kid (a JWE claiming a sender that never registered this key cannot be
 * authenticated, so there is nothing safe to decrypt with).
 *
 * Matches by `#fragment` against the resolved document's OWN current id,
 * not `senderKid` verbatim -- same fix, same reason, as
 * core/identity/webvh-signing-key-resolver.ts's own header: a did:webvh
 * domain move rewrites every verificationMethod's did PREFIX at once, but
 * never the `#fragment` suffix. A sender whose OWN didCommKid was never
 * re-issued (any device other than the one that performed the move) would
 * otherwise become permanently unauthenticatable the instant a SIBLING
 * device moves. */
export async function resolveDidCommSenderKey(senderKid: string, fetchImpl: typeof fetch = defaultFetch()): Promise<Uint8Array> {
  const hash = senderKid.indexOf('#')
  if (hash < 0) throw new Error(`resolveDidCommSenderKey: not a DID URL: ${senderKid}`)
  const did = didOfKid(senderKid)
  const fragment = senderKid.slice(hash)
  if (did.startsWith('did:web:')) {
    const doc = await resolveDidWeb(did, fetchImpl)
    if (!doc) throw new Error(`resolveDidCommSenderKey: sender identity ${did} does not resolve`)
    const vm = doc.verificationMethod?.find(value => value.id === fragment || value.id === senderKid)
    if (!vm) throw new Error(`resolveDidCommSenderKey: ${senderKid} is not a published keyAgreement entry`)
    return decodeX25519Multikey(vm.publicKeyMultibase)
  }
  const doc = await resolve(did, undefined, fetchImpl)
  if (!doc) throw new Error(`resolveDidCommSenderKey: sender identity ${did} does not resolve`)
  const vm = doc.verificationMethod.find(v => v.id === fragment || v.id === `${doc.id}${fragment}`)
  if (!vm) throw new Error(`resolveDidCommSenderKey: ${senderKid} is not a published keyAgreement entry`)
  return decodeX25519Multikey(vm.publicKeyMultibase)
}
