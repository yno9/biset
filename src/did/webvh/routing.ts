// Everything a did:webvh document.ts's WebvhDidDocument can carry that isn't
// load-bearing for identity itself — DIDCommMessaging/JMAPRelay endpoints,
// device keyAgreement keys (X25519 + ML-KEM), display name, alsoKnownAs —
// kept OUT of the signed did:webvh log. did:webvh v1.0 requires only the
// top-level `id` in the DIDDoc — "The DIDDoc can contain any other content
// as deemed necessary by the DID Controller" (spec "Create" step 3) — so
// nothing in the method spec ties any of this to the hash-chained log; only
// the root key (document.ts's own header) actually defines "same identity".
//
// This churns far more often than identity material does too
// (didcomm-devices.ts's registerWithMediator republishes connectivity on
// every boot; devices come and go), and the log has no compaction: y@biset.md
// hit 460 entries / 2.8MB in under 5 days, almost entirely this churn, after
// already having crossed the anchor's 1MiB body limit once (log-io.ts's
// putLog note) — and a single ML-KEM-768 device key alone is over 1600
// base58 characters. Publishing it to a plain, unsigned, always-overwritten
// resource at the DID's own domain/path instead — resolved via the same
// DID-to-HTTPS transform did.jsonl and did-witness.json use — means routine
// churn never touches the log at all.
import { didToResourceUrl } from './identifier.ts'
import type { WebvhService, WebvhVerificationMethod, DidMlkemKeyAgreement } from './document.ts'
import { webvhKeyAgreementId, webvhMlkemKeyAgreementId } from './document.ts'
import { encodeX25519Multikey, encodeMlkem768Multikey } from './multikey.ts'
import type { DidKeyAgreement } from '../document.ts'
import { buildProof, type DataIntegrityProof } from './proof.ts'

export interface RoutingDoc {
  service: WebvhService[]
  // X25519 and ML-KEM device keys, kept as separate arrays (rather than one
  // combined list re-classified on read) so resolver.ts's merge doesn't need
  // to re-derive which is which — the writer already knows.
  keyAgreementVerificationMethod?: WebvhVerificationMethod[]
  mlkemVerificationMethod?: WebvhVerificationMethod[]
  name?: string
  alsoKnownAs?: string[]
}

export function didToRoutingUrl(did: string): string {
  return didToResourceUrl(did, 'routing.json')
}

export interface RoutingInput {
  relays: Array<{ id: string; serverUrl: string; protocol?: string; address?: string }>
  didCommService?: { mediatorUrl: string; routingKey: string }
  keyAgreementKeys?: DidKeyAgreement[]
  mlkemKeyAgreementKeys?: DidMlkemKeyAgreement[]
  name?: string
  addresses?: string | string[]
  /** The DID string this identity was published under BEFORE a domain move
   * (webvh/publish.ts's moveDidToNewDomain) — appended to alsoKnownAs
   * alongside any mailto: addresses. Informational only (did:webvh's
   * portability mechanism needs no pointer to resolve correctly — see
   * publish.ts's own note on this). */
  movedFrom?: string
}

/** Builds the whole RoutingDoc — the `service` array that used to live
 * inline in the DID document's `state` (document.ts's buildBisetWebvhState),
 * plus keyAgreement/name/alsoKnownAs, same shapes as before just assembled
 * for routing.json instead. */
export function buildRoutingDoc(did: string, input: RoutingInput): RoutingDoc {
  const service: WebvhService[] = input.relays.map(r => ({
    id: `${did}#${r.id}`, type: 'JMAPRelay', serviceEndpoint: r.serverUrl.replace(/\/$/, ''),
    protocol: r.protocol, address: r.address,
  }))
  if (input.didCommService) {
    service.push({
      id: `${did}#didcomm`, type: 'DIDCommMessaging',
      serviceEndpoint: { uri: input.didCommService.mediatorUrl, accept: ['didcomm/v2'], routingKeys: [input.didCommService.routingKey] },
    })
  }

  // Sorted by kid for a deterministic document; the order carries no meaning.
  const byKid = (a: { kid: string }, b: { kid: string }) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0)
  const kaKeys = [...(input.keyAgreementKeys ?? [])].sort(byKid)
  const keyAgreementVerificationMethod: WebvhVerificationMethod[] = kaKeys.map(ka => ({
    id: webvhKeyAgreementId(did, ka.kid), type: 'Multikey', controller: did,
    publicKeyMultibase: encodeX25519Multikey(ka.publicKey),
  }))
  const mlkemKaKeys = [...(input.mlkemKeyAgreementKeys ?? [])].sort(byKid)
  const mlkemVerificationMethod: WebvhVerificationMethod[] = mlkemKaKeys.map(ka => ({
    id: webvhMlkemKeyAgreementId(did, ka.kid), type: 'Multikey', controller: did,
    publicKeyMultibase: encodeMlkem768Multikey(ka.publicKey),
  }))

  const addrs = (Array.isArray(input.addresses) ? input.addresses : input.addresses ? [input.addresses] : []).filter(Boolean)
  const alsoKnownAs = [...addrs.map(a => `mailto:${a}`), ...(input.movedFrom ? [input.movedFrom] : [])]

  return {
    service,
    ...(keyAgreementVerificationMethod.length ? { keyAgreementVerificationMethod } : {}),
    ...(mlkemVerificationMethod.length ? { mlkemVerificationMethod } : {}),
    ...(input.name ? { name: input.name } : {}),
    ...(alsoKnownAs.length ? { alsoKnownAs } : {}),
  }
}

/** GET, treating a missing file as "not registered yet" rather than an
 * error — every existing reader of a resolved document's `service`/
 * `keyAgreement`/`name`/`alsoKnownAs` already handles an absent entry
 * gracefully, so a 404 here just reproduces that same, already-tolerated
 * state. */
export async function fetchRouting(did: string, init?: RequestInit): Promise<RoutingDoc | null> {
  const resp = await fetch(didToRoutingUrl(did), init)
  if (resp.status === 404) return null
  if (!resp.ok) throw new Error(`fetchRouting: GET failed with HTTP ${resp.status}`)
  return (await resp.json()) as RoutingDoc
}

/** Whole-document PUT — unlike did.jsonl there is no history to preserve, so
 * there is no append/CAS concern to design around (log-io.ts's putLog exists
 * only because the log itself must never be replaced).
 *
 * Unlike did.jsonl, routing.json's own content carries no self-certifying
 * structure (no hash chain, no per-entry proof) — without SOME signature an
 * open PUT endpoint would let any third party redirect another identity's
 * mail/DIDComm delivery, or plant a fake device key, outright. Reuses the
 * exact same DataIntegrityProof (proof.ts) a log entry signs with, over the
 * whole RoutingDoc — the anchor verifies it against the identity's CURRENT
 * updateKeys (server.ts's handleRouting) before accepting a write, same
 * authorization check updateDocument itself runs before ever reaching this
 * call. */
export async function putRouting(
  did: string, doc: RoutingDoc, signing: { updateKey: string; privateKey: Uint8Array },
): Promise<void> {
  const proof: DataIntegrityProof = buildProof(doc, {
    verificationMethod: `did:key:${signing.updateKey}#${signing.updateKey}`,
    privateKey: signing.privateKey,
  })
  const resp = await fetch(didToRoutingUrl(did), {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...doc, proof }),
  })
  if (!resp.ok) throw new Error(`putRouting: PUT failed with HTTP ${resp.status} ${await resp.text().catch(() => '')}`)
}
