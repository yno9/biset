// biset's did:webvh DID Document ("state") builder — the W3C DID Core JSON
// shape a did:webvh log entry's `state` field carries directly (unlike
// did:dht, whose DNS-record encoding needs its own codec — see
// dht/document.ts).
//
// Minimal by design (2026-08-17): did:webvh v1.0 requires only the top-level
// `id` in the DIDDoc ("The DIDDoc can contain any other content as deemed
// necessary by the DID Controller" — spec's own "Create" step 3), and the
// log has no compaction, so anything that isn't actually load-bearing for
// PROVING this identity is the same one across time costs bytes forever.
// Sorted into what stays signed and what moved to routing.ts's sibling
// resource:
//
//   id / verificationMethod[0] (#key-1) / authentication  — identity itself:
//     the root key IS what "same identity" means here, and the hash chain
//     only has meaning relative to it. Stays.
//   assertionMethod — pure duplication of #key-1 via a second relationship
//     name nothing here ever used. Dropped outright, not even relocated.
//   keyAgreement (X25519 + ML-KEM device keys), alsoKnownAs, name —
//     operational/self-asserted data that churns with device and relay
//     churn, never with "is this still the same identity". Moved to
//     routing.ts; resolver.ts merges it back in on read so every existing
//     consumer of a resolved WebvhDidDocument stays oblivious to where it
//     came from.
//   service — almost entirely moved too, EXCEPT one constant pointer entry
//     (`#routing`, added 2026-08-17) naming where routing.json actually
//     lives. Without it, nothing in did.jsonl signals routing.json exists at
//     all — a resolver has to already know biset's private filename
//     convention to find it, which is unfriendly to exactly the kind of
//     third party did:webvh's own "override the implicit DID URL resolution
//     with an explicit service" mechanism (spec's DID URL Handling section,
//     the same mechanism `/whois` uses) exists to help. This entry never
//     changes after genesis, so it costs one one-time write, never a
//     recurring one — resolver.ts's mergeRouting concatenates it with
//     routing.json's own service list rather than replacing wholesale, so
//     it survives every merge.
import { encodeMultikey, decodeMultikey, decodeX25519Multikey, decodeMlkem768Multikey } from './multikey.ts'
import { fragmentOf, isDeviceKid, isMlkemKid, mlkemKidFor, deviceKidForMlkem } from '../devicekid.ts'
import type { DidKeyAgreement } from '../document.ts'
import { didToResourceUrl } from './identifier.ts'

// ML-KEM-768 keyAgreement key (PLAN.md "did:webvh PQハイブリッド化", Phase 1) —
// webvh-only (did:dht is explicitly out of scope, PLAN.md §1: BEP44's 1000-byte
// record cap can't fit a 1184-byte ML-KEM-768 public key). Same slot-number
// concept as DidKeyAgreement (dht/document.ts), paired to the X25519 entry at
// the same `n` — one entry per registered device, kept as its own type rather
// than folded into DidKeyAgreement since that type is shared with did:dht.
export interface DidMlkemKeyAgreement {
  /** The FRAGMENT of the X25519 device kid this ML-KEM key belongs to
   * (`#k1`, `#k_<hash>`) — NOT its own `#kk…` id, which is derived from it.
   * Pairing by a shared suffix replaces pairing by slot number; see
   * devicekid.ts's mlkemKidFor. */
  kid: string
  publicKey: Uint8Array
}

/** A DIDCommMessaging endpoint as DIDComm v2 defines it: `accept` and
 * `routingKeys` live INSIDE `serviceEndpoint`, not beside it. */
export interface DidCommServiceEndpoint {
  uri: string
  accept: string[]
  routingKeys: string[]
}

export interface WebvhService {
  id: string
  type: string
  serviceEndpoint: string | string[] | DidCommServiceEndpoint
  protocol?: string
  address?: string
  /** @deprecated The pre-DIDComm-v2 placement: these belong inside
   * `serviceEndpoint`. Still READ so documents published before the change
   * keep working (didcomm/resolve.ts accepts either), never written. */
  accept?: string[]
  routingKeys?: string[]
}

export interface WebvhVerificationMethod {
  id: string
  type: 'Multikey'
  controller: string
  publicKeyMultibase: string
}

export interface WebvhDidDocument {
  '@context': string[]
  id: string
  verificationMethod: WebvhVerificationMethod[]
  authentication: string[]
  // Present only when this identity has at least one registered DIDComm
  // device key — array of verificationMethod ids, W3C DID Core standard
  // shape (unlike did:dht's positional _k<n> DNS records). Sourced from
  // routing.json on a resolved document (resolver.ts) — see this file's own
  // header note.
  keyAgreement?: string[]
  service: WebvhService[]
  alsoKnownAs: string[]
  name?: string
}

// A device key's verification-method id is the DID plus its kid fragment —
// the kid IS the name, derived from the key itself (devicekid.ts), and this
// function only joins the two. Same fragment shape dht/document.ts uses, so
// the shared multi-device logic (didcomm-devices.ts) stays method-agnostic.
export function webvhKeyAgreementId(did: string, kidFragment: string): string {
  return `${did}${fragmentOf(kidFragment)}`
}

// ML-KEM-768 counterpart's verification-method id: the same suffix under the
// `#kk` prefix (devicekid.ts's mlkemKidFor), so the pair is readable from the
// strings alone. `#kk…` and `#k…` stay distinguishable by prefix because a
// derived X25519 suffix always starts with `_` and a legacy one with a digit.
export function webvhMlkemKeyAgreementId(did: string, kidFragment: string): string {
  return `${did}${mlkemKidFor(fragmentOf(kidFragment))}`
}

/** The signed log entry's own `state` shape — narrower than a resolved
 * WebvhDidDocument. `alsoKnownAs` is deliberately absent rather than written
 * as `[]`: resolver.ts's mergeRouting overwrites it unconditionally on every
 * resolve regardless of what the raw state holds, so writing an empty array
 * into the signed bytes buys nothing but a dead key forever. `service` DOES
 * stay — see this file's header on the one pointer entry it always carries. */
export type SignedWebvhState = Omit<WebvhDidDocument, 'alsoKnownAs'>

/** did.jsonl and routing.json are logically beside each other (both under
 * the DID's own domain/path, identifier.ts's didToResourceUrl) — kept as a
 * literal here rather than importing routing.ts's own didToRoutingUrl to
 * avoid a cycle (routing.ts already imports this file for WebvhService).
 * Must name the exact same file routing.ts's own functions read/write. */
const ROUTING_FILENAME = 'routing.json'

/** Builds the always-minimal signed state: `id`, the one key that defines
 * this identity, and a constant pointer to where routing.json lives (this
 * file's header explains why that one entry stays signed while everything
 * else in `service` doesn't). Everything else a resolved WebvhDidDocument
 * carries (keyAgreement, the rest of service, alsoKnownAs, name) comes from
 * routing.ts/resolver.ts instead. */
export function buildBisetWebvhState(did: string, rootPublicKey: Uint8Array): SignedWebvhState {
  const keyId = `${did}#key-1`
  return {
    // Multikey is what verificationMethod uses, and it is defined by the
    // security vocabulary rather than by DID Core — a document that names
    // the type without the context that defines it is only readable by
    // implementations that already assume it. did:webvh hashes with JCS
    // rather than JSON-LD canonicalization, so this costs nothing at
    // verification time and makes the document self-describing for
    // everyone else.
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [{ id: keyId, type: 'Multikey', controller: did, publicKeyMultibase: encodeMultikey(rootPublicKey) }],
    authentication: [keyId],
    service: [{ id: `${did}#routing`, type: 'BisetRoutingDocument', serviceEndpoint: didToResourceUrl(did, ROUTING_FILENAME) }],
  }
}

/** The root (authentication) Ed25519 public key a resolved document names —
 * did:webvh's counterpart to didbind.ts's did:dht `didPublicKey` (there the
 * DID *is* the key; here it only names a verificationMethod, so a resolved
 * document is required to get it). Used to verify a DID.md binding proof
 * (anchor/didbind.ts) for a did:webvh claimant. */
export function rootPublicKeyFromWebvhState(doc: WebvhDidDocument): Uint8Array | null {
  const kid = doc.authentication[0]
  const vm = doc.verificationMethod.find(v => v.id === kid)
  if (!vm) return null
  try { return decodeMultikey(vm.publicKeyMultibase) } catch { return null }
}

/** Extracts the keyAgreement X25519 keys back out of a resolved document —
 * the read-side counterpart to routing.ts's keyAgreementKeys option. Reads
 * verificationMethod entries named by the `keyAgreement` id list; the
 * fragment IS the kid, so nothing is parsed out of it. */
export function keyAgreementKeysFromWebvhState(doc: WebvhDidDocument): DidKeyAgreement[] {
  const ids = new Set(doc.keyAgreement ?? [])
  const out: DidKeyAgreement[] = []
  for (const vm of doc.verificationMethod) {
    if (!ids.has(vm.id)) continue
    const kid = fragmentOf(vm.id)
    if (!isDeviceKid(kid)) continue
    try { out.push({ kid, publicKey: decodeX25519Multikey(vm.publicKeyMultibase) }) } catch { /* skip malformed entry */ }
  }
  return out
}

/** ML-KEM-768 counterpart of keyAgreementKeysFromWebvhState — reads back the
 * `#kk…` entries a PQ-capable device published alongside its X25519 one. */
export function mlkemKeyAgreementKeysFromWebvhState(doc: WebvhDidDocument): DidMlkemKeyAgreement[] {
  const out: DidMlkemKeyAgreement[] = []
  for (const vm of doc.verificationMethod) {
    // Read from verificationMethod alone: these are deliberately not in
    // `keyAgreement` (see routing.ts's buildRoutingDoc), so requiring them
    // to be listed there would find nothing.
    const kid = fragmentOf(vm.id)
    if (!isMlkemKid(kid)) continue
    // Stored under the X25519 kid it belongs to, not its own — that is the
    // key the rest of the code pairs it with.
    try { out.push({ kid: deviceKidForMlkem(kid), publicKey: decodeMlkem768Multikey(vm.publicKeyMultibase) }) } catch { /* skip malformed entry */ }
  }
  return out
}
