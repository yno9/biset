// routing.json: everything a did:webvh identity's DID document can carry
// that isn't load-bearing for identity itself — kept OUT of the signed
// did:webvh log (identifier.ts's own genesis/update entries stay minimal,
// PLAN.md's identity-generation scope). did:webvh v1.0 requires only the
// top-level `id` in the DIDDoc, so nothing in the method spec ties this to
// the hash-chained log; only the root key actually defines "same identity".
//
// Ported from src.bak/did/webvh/routing.ts, narrowed to what this rewrite's
// DIDComm adapter (PLAN.md §6.1) actually needs: the DIDCommMessaging
// service entry and a device's X25519/ML-KEM-768 keyAgreement keys. Dropped
// relative to the source: the old JMAPRelay service-list entries (this
// rewrite's mail adapter resolves recipients from DNS/subdomain convention,
// not a routing.json relay list — mail-recipient-resolver.ts) and
// name/alsoKnownAs (nothing in this rewrite reads them yet).
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { buildProof, type DataIntegrityProof } from '../identity/webvh/proof.ts'
import type { WebvhService, WebvhVerificationMethod } from '../identity/webvh/document.ts'
import { encodeX25519Multikey, encodeMlkem768Multikey } from './multikey.ts'
import { fragmentOf, mlkemKidFor } from './devicekid.ts'

/** A DIDCommMessaging endpoint as DIDComm v2 defines it: `accept` and
 * `routingKeys` live INSIDE `serviceEndpoint`, not beside it. `routingKeys`
 * is deliberately never populated by buildRoutingDoc: an empty routingKeys
 * (equivalently, the field's absence) is what tells a spec-compliant
 * DIDComm sender NOT to Forward-wrap (see crypto.ts's own header) — this
 * rewrite's adapter is first-party infrastructure, not a blind mediator, so
 * there is never a routing key to name. */
export interface DidCommServiceEndpoint extends Record<string, unknown> {
  uri: string
  accept: string[]
  routingKeys: string[]
}

export interface RoutingDoc {
  service: WebvhService[]
  // X25519 and ML-KEM device keys, kept as separate arrays (rather than one
  // combined list re-classified on read) so the reader doesn't need to
  // re-derive which is which — the writer already knows.
  keyAgreementVerificationMethod?: WebvhVerificationMethod[]
  mlkemVerificationMethod?: WebvhVerificationMethod[]
}

/** did.jsonl and routing.json are logically beside each other, both under
 * the DID's own domain (subdomain-per-identity, no pathSegments in this
 * rewrite's convention — create-genesis.ts). Same transform as
 * identity/webvh/identifier.ts's didToHttpsUrl, parameterized by filename;
 * kept local rather than exported from there since that module is a
 * deliberately read-only, signing-only subset (its own header). */
export function didToRoutingUrl(did: string): string {
  const { domain, port } = parseWebvhDid(did)
  const hostname = new URL(`https://${domain}`).hostname
  const hostPart = port ? `${hostname}:${port}` : hostname
  return `https://${hostPart}/.well-known/routing.json`
}

export interface DidKeyAgreement { kid: string; publicKey: Uint8Array }
export interface DidMlkemKeyAgreement { kid: string; publicKey: Uint8Array }

export interface RoutingInput {
  /** This identity's DIDComm ingress endpoint (this deployment's
   * `POST /v1/didcomm/ingress`, e.g. `https://biset.md/v1/didcomm/ingress`)
   * -- omitted when this identity has no DIDComm-capable device yet. */
  didCommEndpoint?: string
  keyAgreementKeys?: DidKeyAgreement[]
  mlkemKeyAgreementKeys?: DidMlkemKeyAgreement[]
}

// A device key's verification-method id is the DID plus its kid fragment —
// the kid IS the name, derived from the key itself (devicekid.ts). The
// ML-KEM-768 counterpart's id is the same suffix under the `#kk` prefix
// (devicekid.ts's mlkemKidFor), so the pair is readable from the strings
// alone.
function webvhKeyAgreementId(did: string, kidFragment: string): string {
  return `${did}${fragmentOf(kidFragment)}`
}

function webvhMlkemKeyAgreementId(did: string, kidFragment: string): string {
  return `${did}${mlkemKidFor(fragmentOf(kidFragment))}`
}

/** Builds the whole RoutingDoc. Sorted by kid for a deterministic document;
 * the order carries no meaning. */
export function buildRoutingDoc(did: string, input: RoutingInput): RoutingDoc {
  const service: WebvhService[] = input.didCommEndpoint
    ? [{ id: `${did}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: input.didCommEndpoint, accept: ['didcomm/v2'], routingKeys: [] } satisfies DidCommServiceEndpoint }]
    : []

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

  return {
    service,
    ...(keyAgreementVerificationMethod.length ? { keyAgreementVerificationMethod } : {}),
    ...(mlkemVerificationMethod.length ? { mlkemVerificationMethod } : {}),
  }
}

/** GET, treating a missing file as "not registered yet" rather than an
 * error — every reader of a resolved document's `service`/`keyAgreement`
 * already handles an absent entry gracefully. */
export async function fetchRouting(did: string, fetchImpl: typeof fetch, init?: RequestInit): Promise<RoutingDoc | null> {
  const resp = await fetchImpl(didToRoutingUrl(did), init)
  if (resp.status === 404) return null
  if (!resp.ok) throw new Error(`fetchRouting: GET failed with HTTP ${resp.status}`)
  return (await resp.json()) as RoutingDoc
}

/** Whole-document PUT — unlike did.jsonl there is no history to preserve, so
 * there is no append/CAS concern to design around.
 *
 * Unlike did.jsonl, routing.json's own content carries no self-certifying
 * structure (no hash chain, no per-entry proof) — without SOME signature an
 * open PUT endpoint would let any third party redirect another identity's
 * DIDComm delivery, or plant a fake device key, outright. Reuses the exact
 * same DataIntegrityProof (identity/webvh/proof.ts) a log entry signs with,
 * over the whole RoutingDoc — the server verifies it against the identity's
 * CURRENT updateKeys before accepting a write. */
export async function putRouting(
  did: string, doc: RoutingDoc, signing: { updateKey: string; privateKey: Uint8Array }, fetchImpl: typeof fetch,
): Promise<void> {
  const proof: DataIntegrityProof = buildProof(doc, {
    verificationMethod: `did:key:${signing.updateKey}#${signing.updateKey}`,
    privateKey: signing.privateKey,
  })
  const resp = await fetchImpl(didToRoutingUrl(did), {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...doc, proof }),
  })
  if (!resp.ok) throw new Error(`putRouting: PUT failed with HTTP ${resp.status} ${await resp.text().catch(() => '')}`)
}
