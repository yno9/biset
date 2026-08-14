// biset's did:webvh DID Document ("state") builder — the W3C DID Core JSON
// shape a did:webvh log entry's `state` field carries directly (unlike
// did:dht, whose DNS-record encoding needs its own codec — see
// dht/document.ts). Mirrors dht/document.ts's buildBisetDocument argument
// shape so call sites (didcomm-devices.ts, webvh/publish.ts) branch on
// method without relearning a different signature.
import {
  encodeMultikey, decodeMultikey, encodeX25519Multikey, decodeX25519Multikey,
  encodeMlkem768Multikey, decodeMlkem768Multikey,
} from './multikey.ts'
import { fragmentOf, isDeviceKid, isMlkemKid, mlkemKidFor, deviceKidForMlkem } from '../devicekid.ts'
import type { DidKeyAgreement } from '../dht/document.ts'

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
  assertionMethod: string[]
  // Present only when this identity has at least one registered DIDComm
  // device key — array of verificationMethod ids, W3C DID Core standard
  // shape (unlike did:dht's positional _k<n> DNS records).
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

export interface DidCommServiceOpts {
  mediatorUrl: string
  routingKey: string
}

export interface BuildWebvhStateOpts {
  keyAgreementKeys?: DidKeyAgreement[]
  // Paired by slot number with keyAgreementKeys — a device that has published
  // an X25519 entry at `n` MAY also have one here at the same `n` (PQ-capable
  // device); absence just means that device's ML-KEM-768 key hasn't
  // propagated yet or the whole identity predates PQ support, not an error.
  mlkemKeyAgreementKeys?: DidMlkemKeyAgreement[]
  didCommService?: DidCommServiceOpts
  name?: string
  /** The DID string this identity was published under BEFORE a domain move
   * (webvh/publish.ts's moveDidToNewDomain, PLANWEBVH.md §9) — appended to
   * alsoKnownAs alongside any mailto: addresses.
   *
   * Informational only. Under did:webvh's portability mechanism the move
   * appends to the SAME log (same SCID), so resolution needs no pointer at
   * all in either direction: the old location serves that same log, and
   * resolving the old DID matches its genesis entry and returns the latest
   * state. This replaced a `movedTo` forward-pointer that the superseded
   * new-genesis implementation depended on, where two unrelated logs meant a
   * pointer was the ONLY link between them. */
  movedFrom?: string
}

export function buildBisetWebvhState(
  did: string,
  rootPublicKey: Uint8Array,
  relays: Array<{ id: string; serverUrl: string; protocol?: string; address?: string }>,
  addresses: string | string[],
  opts: BuildWebvhStateOpts = {},
): WebvhDidDocument {
  const addrs = (Array.isArray(addresses) ? addresses : [addresses]).filter(Boolean)
  const keyId = `${did}#key-1`
  const verificationMethod: WebvhVerificationMethod[] = [
    { id: keyId, type: 'Multikey', controller: did, publicKeyMultibase: encodeMultikey(rootPublicKey) },
  ]

  // Sorted by kid for a deterministic document; the order carries no meaning.
  const byKid = (a: { kid: string }, b: { kid: string }) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0)
  const kaKeys = [...(opts.keyAgreementKeys ?? [])].sort(byKid)
  for (const ka of kaKeys) {
    verificationMethod.push({
      id: webvhKeyAgreementId(did, ka.kid), type: 'Multikey', controller: did,
      publicKeyMultibase: encodeX25519Multikey(ka.publicKey),
    })
  }
  const mlkemKaKeys = [...(opts.mlkemKeyAgreementKeys ?? [])].sort(byKid)
  for (const ka of mlkemKaKeys) {
    verificationMethod.push({
      id: webvhMlkemKeyAgreementId(did, ka.kid), type: 'Multikey', controller: did,
      publicKeyMultibase: encodeMlkem768Multikey(ka.publicKey),
    })
  }

  const service: WebvhService[] = relays.map(r => ({
    id: `${did}#${r.id}`, type: 'JMAPRelay', serviceEndpoint: r.serverUrl.replace(/\/$/, ''),
    protocol: r.protocol, address: r.address,
  }))
  if (opts.didCommService) {
    service.push({
      // DIDComm v2's own shape: one object carrying uri/accept/routingKeys.
      // This used to publish the endpoint as an array with `accept` and
      // `routingKeys` as SIBLINGS of it, which is the pre-v2 placement — a
      // conforming agent reading that finds the mediator's URI and no routing
      // keys, so it cannot Forward to us at all. biset's own resolver read the
      // flat form, which is why nothing here noticed.
      id: `${did}#didcomm`, type: 'DIDCommMessaging',
      serviceEndpoint: { uri: opts.didCommService.mediatorUrl, accept: ['didcomm/v2'], routingKeys: [opts.didCommService.routingKey] },
    })
  }

  return {
    // Multikey is what every verificationMethod here uses, and it is defined
    // by the security vocabulary rather than by DID Core — a document that
    // names the type without the context that defines it is only readable by
    // implementations that already assume it. did:webvh hashes with JCS rather
    // than JSON-LD canonicalization, so this costs nothing at verification
    // time and makes the document self-describing for everyone else.
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod,
    authentication: [keyId],
    assertionMethod: [keyId],
    // ML-KEM entries are deliberately NOT in `keyAgreement`.
    //
    // `keyAgreement` means "you may run key agreement with these". Every
    // implementation but this one reads that as X25519-shaped ECDH, so listing
    // 1184-byte ML-KEM keys there hands a conforming agent a list where half
    // the entries fail — and biset's own resolver only avoided it by filtering
    // on a naming convention nobody else knows (didcomm/resolve.ts).
    //
    // They stay in `verificationMethod`, which is where a key that exists but
    // has no standard relationship belongs. biset pairs each with its device
    // by the shared kid suffix (devicekid.ts's mlkemKidFor) and reads it from
    // there; anyone else simply sees keys they have no use for, which is the
    // honest state of affairs while MLS/DIDComm PQ hybrids are pre-standard.
    ...(kaKeys.length ? { keyAgreement: kaKeys.map(ka => webvhKeyAgreementId(did, ka.kid)) } : {}),
    service,
    alsoKnownAs: [...addrs.map(a => `mailto:${a}`), ...(opts.movedFrom ? [opts.movedFrom] : [])],
    ...(opts.name ? { name: opts.name } : {}),
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
 * the read-side counterpart to buildBisetWebvhState's keyAgreementKeys
 * option. Reads verificationMethod entries named by the `keyAgreement` id
 * list; the fragment IS the kid, so nothing is parsed out of it. */
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
    // `keyAgreement` (see buildBisetWebvhState), so requiring them to be
    // listed there would find nothing.
    const kid = fragmentOf(vm.id)
    if (!isMlkemKid(kid)) continue
    // Stored under the X25519 kid it belongs to, not its own — that is the
    // key the rest of the code pairs it with.
    try { out.push({ kid: deviceKidForMlkem(kid), publicKey: decodeMlkem768Multikey(vm.publicKeyMultibase) }) } catch { /* skip malformed entry */ }
  }
  return out
}
