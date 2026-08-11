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
import type { DidKeyAgreement } from '../dht/document.ts'

// ML-KEM-768 keyAgreement key (PLAN.md "did:webvh PQハイブリッド化", Phase 1) —
// webvh-only (did:dht is explicitly out of scope, PLAN.md §1: BEP44's 1000-byte
// record cap can't fit a 1184-byte ML-KEM-768 public key). Same slot-number
// concept as DidKeyAgreement (dht/document.ts), paired to the X25519 entry at
// the same `n` — one entry per registered device, kept as its own type rather
// than folded into DidKeyAgreement since that type is shared with did:dht.
export interface DidMlkemKeyAgreement { n: number; publicKey: Uint8Array }

export interface WebvhService {
  id: string
  type: string
  serviceEndpoint: string | string[]
  protocol?: string
  address?: string
  // DIDCommMessaging extension (W3C-standard fields, mirrors dht/document.ts's
  // DidService — an identity's mediator is reached through its own routing
  // key, and the client declares which DIDComm versions it accepts).
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
  // biset extension (same purpose as dht/document.ts's removedKeyNs): device
  // slot numbers deliberately revoked, carried on the document itself so
  // every OTHER device (and any resolver) learns about a removal too.
  removedKeyNs?: number[]
  name?: string
}

// keyAgreement verification-method id scheme: `{did}#k{n}` — deliberately the
// SAME fragment shape dht/document.ts uses (`_k<n>` there, `#k<n>` here as a
// DID URL fragment), so kidN()/keyAgreementKeysFromHex() (dht/document.ts) —
// both already method-agnostic in content — can be reused verbatim by the
// shared multi-device logic (didcomm-devices.ts) instead of reimplemented.
export function webvhKeyAgreementId(did: string, n: number): string {
  return `${did}#k${n}`
}

// ML-KEM-768 counterpart's verification-method id — `#kk{n}`, deliberately
// distinct from `#k{n}` (never matched by the `/#k(\d+)$/` pattern
// keyAgreementKeysFromWebvhState/kidN use, since `k` isn't a digit) so the two
// key types coexist in one keyAgreement list without either parser
// misreading the other's entries.
export function webvhMlkemKeyAgreementId(did: string, n: number): string {
  return `${did}#kk${n}`
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
  removedKeyNs?: number[]
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

  const kaKeys = [...(opts.keyAgreementKeys ?? [])].sort((a, b) => a.n - b.n)
  for (const ka of kaKeys) {
    verificationMethod.push({
      id: webvhKeyAgreementId(did, ka.n), type: 'Multikey', controller: did,
      publicKeyMultibase: encodeX25519Multikey(ka.publicKey),
    })
  }
  const mlkemKaKeys = [...(opts.mlkemKeyAgreementKeys ?? [])].sort((a, b) => a.n - b.n)
  for (const ka of mlkemKaKeys) {
    verificationMethod.push({
      id: webvhMlkemKeyAgreementId(did, ka.n), type: 'Multikey', controller: did,
      publicKeyMultibase: encodeMlkem768Multikey(ka.publicKey),
    })
  }

  const service: WebvhService[] = relays.map(r => ({
    id: `${did}#${r.id}`, type: 'JMAPRelay', serviceEndpoint: r.serverUrl.replace(/\/$/, ''),
    protocol: r.protocol, address: r.address,
  }))
  if (opts.didCommService) {
    service.push({
      id: `${did}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: [opts.didCommService.mediatorUrl],
      accept: ['didcomm/v2'], routingKeys: [opts.didCommService.routingKey],
    })
  }

  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod,
    authentication: [keyId],
    assertionMethod: [keyId],
    ...(kaKeys.length || mlkemKaKeys.length ? {
      keyAgreement: [
        ...kaKeys.map(ka => webvhKeyAgreementId(did, ka.n)),
        ...mlkemKaKeys.map(ka => webvhMlkemKeyAgreementId(did, ka.n)),
      ],
    } : {}),
    service,
    alsoKnownAs: [...addrs.map(a => `mailto:${a}`), ...(opts.movedFrom ? [opts.movedFrom] : [])],
    ...(opts.removedKeyNs?.length ? { removedKeyNs: opts.removedKeyNs } : {}),
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
 * list, parses each `#k<n>` fragment for its slot number (dht/document.ts's
 * kidN, applied to the DID URL fragment). */
export function keyAgreementKeysFromWebvhState(doc: WebvhDidDocument): DidKeyAgreement[] {
  const ids = new Set(doc.keyAgreement ?? [])
  const out: DidKeyAgreement[] = []
  for (const vm of doc.verificationMethod) {
    if (!ids.has(vm.id)) continue
    const m = /#k(\d+)$/.exec(vm.id)
    if (!m) continue
    try { out.push({ n: Number(m[1]), publicKey: decodeX25519Multikey(vm.publicKeyMultibase) }) } catch { /* skip malformed entry */ }
  }
  return out
}

/** ML-KEM-768 counterpart of keyAgreementKeysFromWebvhState — reads back the
 * `#kk<n>` entries a PQ-capable device published alongside its X25519 one. */
export function mlkemKeyAgreementKeysFromWebvhState(doc: WebvhDidDocument): DidMlkemKeyAgreement[] {
  const ids = new Set(doc.keyAgreement ?? [])
  const out: DidMlkemKeyAgreement[] = []
  for (const vm of doc.verificationMethod) {
    if (!ids.has(vm.id)) continue
    const m = /#kk(\d+)$/.exec(vm.id)
    if (!m) continue
    try { out.push({ n: Number(m[1]), publicKey: decodeMlkem768Multikey(vm.publicKeyMultibase) }) } catch { /* skip malformed entry */ }
  }
  return out
}
