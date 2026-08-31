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
// not a routing.json relay list — mail-recipient-resolver.ts).
//
// alsoKnownAs/name were dropped too at first ("nothing in this rewrite reads
// them yet") -- restored 2026-08-26 after user feedback: `enableDidComm`
// (identity/bootstrap.ts) now publishes this identity's own derived mail
// address into `alsoKnownAs` (nothing else ever asserted the DID<->mail
// link anywhere), and account-page.ts's "Edit identity" writes a
// self-asserted `name`.
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { buildProof, type DataIntegrityProof } from '../identity/webvh/proof.ts'
import type { WebvhService, WebvhVerificationMethod } from '../identity/webvh/document.ts'
import { encodeX25519Multikey, encodeMlkem768Multikey } from './multikey.ts'
import { fragmentOf, mlkemKidFor } from './devicekid.ts'

/** A DIDCommMessaging endpoint as DIDComm v2 defines it: `accept` and
 * `routingKeys` live INSIDE `serviceEndpoint`, not beside it.
 *
 * Until the 2026-08-27 mediator redesign (ARC.md), `routingKeys` was
 * deliberately never populated here: an empty routingKeys (equivalently,
 * the field's absence) is what tells a spec-compliant DIDComm sender NOT to
 * Forward-wrap (see crypto.ts's own header), and this adapter used to be
 * first-party infrastructure with no routing key to name. Now that
 * `enableDidComm` can register this identity with an independent, blind
 * mediator (mediator-sync.ts's `registerWithMediator`), a device WITH one
 * publishes `routingKeys: [mediatorRoutingKid]` and `uri` pointing at that
 * mediator's own HTTP endpoint -- telling a sender to authcrypt to
 * `keyAgreementVerificationMethod` as before, then anoncrypt-Forward-wrap
 * to the mediator (send-message.ts). A device with no registered mediator
 * still gets `routingKeys: []` (the legacy `didCommEndpoint` fallback,
 * `buildRoutingDoc` below) — direct delivery, unchanged. */
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
  /** Other identifiers this identity is known to answer to -- currently just
   * the derived mail address (identity/bootstrap.ts's mailFromForIdentity),
   * published so a third party resolving the DID can verify the mail<->DID
   * link instead of taking it on faith. */
  alsoKnownAs?: string[]
  /** Self-asserted display name (account-page.ts's "Edit identity") --
   * unverified, same trust level as any profile display name anywhere. */
  name?: string
  /** This identity's current OpenPGP public certificate (mail/enable-openpgp.ts),
   * published here so any other identity resolving this DID can encrypt
   * outbound mail to it without a separate WKD/Autocrypt lookup. Unlike
   * keyAgreementVerificationMethod (one entry per device -- DIDComm's own
   * multi-recipient JWE support makes that the right shape there), PGP has
   * no native multi-device story: this is the SAME private key synced
   * identity-wide across every trusted device via
   * vault/openpgp-credential.ts, so there is exactly one current public key
   * to publish, not one per device. */
  openpgpPublicKey?: RoutingOpenPgpKey
}

export interface RoutingOpenPgpKey {
  fingerprint: string
  armoredPublicKey: string
  createdAt: string
  supersedesFingerprint?: string
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

/** One independent mediator this identity has registered a kid with
 * (mediator-sync.ts's `registerWithMediator`). `routingKid` is the
 * mediator's OWN did:peer keyAgreement kid (what a sender anoncrypts the
 * Forward envelope to -- decodable straight from the kid string, no
 * network resolve needed, since did:peer is self-certifying). */
export interface MediatorRegistration { url: string; routingKid: string }

/** This identity's Conversation Group MLS Delivery Service endpoint
 * (mls-ds/http.ts, PLAN_biset-mls-ds.md §11-7). Published as its own
 * service entry alongside `DIDCommMessaging` rather than folded into it --
 * biset's own DIDComm-binding path (mls-ds-1.0.md, Phase 2b) still exists
 * as a separate, independent access path to the same DS engine, so the two
 * transports get two discoverable entries. A third party that resolves
 * this DID and already knows how to reach a `MimiDeliveryService` entry
 * can connect directly, skipping DIDComm mediator relay entirely --
 * PLAN_biset-mls-ds.md §11-7's "mediator-less" finding, made resolvable.
 * `MimiDeliveryService` is a biset-defined type, not a registered MIMI/DID
 * spec term -- MIMI itself doesn't standardize DID-based provider discovery
 * (confirmed by research, not just unfound). Publishing it anyway is a
 * "works for biset now, and for anyone else who adopts the same service
 * type later" bet, not a claim of any existing standard. */
export interface MimiProviderRegistration { url: string }

export interface RoutingInput {
  /** Legacy direct-delivery endpoint (this deployment's own
   * `POST /v1/didcomm/ingress`) -- superseded by `mediators` when both are
   * given (buildRoutingDoc below). Kept for an identity that hasn't
   * registered with any mediator yet; ARC.md's Phase 6 removes this once
   * the mediator path has fully replaced it. */
  didCommEndpoint?: string
  /** Independent, blind mediators registered for this identity's shared
   * DIDComm kid (ARC.md's 2026-08-27 redesign) -- each becomes one
   * DIDCommMessaging service entry whose `routingKeys` names that
   * mediator's kid, so a spec-compliant sender Forward-wraps through it
   * instead of delivering directly. */
  mediators?: MediatorRegistration[]
  /** This identity's Conversation Group DS, if it has registered one --
   * see MimiProviderRegistration's own note. */
  mimiProvider?: MimiProviderRegistration
  keyAgreementKeys?: DidKeyAgreement[]
  mlkemKeyAgreementKeys?: DidMlkemKeyAgreement[]
  alsoKnownAs?: string[]
  name?: string
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
  // `mediators` supersedes the legacy direct endpoint when both are given —
  // a device that has registered with a mediator should stop advertising
  // the old first-party path, not offer both (a sender would have no way to
  // choose between two equally-valid-looking entries with different privacy
  // properties).
  const didCommService: WebvhService[] = input.mediators?.length
    ? input.mediators.map((m, i): WebvhService => ({
        id: `${did}#didcomm${input.mediators!.length > 1 ? `-${i + 1}` : ''}`,
        type: 'DIDCommMessaging',
        serviceEndpoint: { uri: m.url, accept: ['didcomm/v2'], routingKeys: [m.routingKid] } satisfies DidCommServiceEndpoint,
      }))
    : input.didCommEndpoint
      ? [{ id: `${did}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: input.didCommEndpoint, accept: ['didcomm/v2'], routingKeys: [] } satisfies DidCommServiceEndpoint }]
      : []
  // Listed alongside DIDCommMessaging, not instead of it -- a resolver that
  // doesn't recognize `MimiDeliveryService` simply sees one extra service
  // entry and falls back to DIDComm, same graceful-degradation shape as any
  // unrecognized service type in DID Core.
  const mimiService: WebvhService[] = input.mimiProvider ? [{ id: `${did}#mimi-ds`, type: 'MimiDeliveryService', serviceEndpoint: input.mimiProvider.url }] : []
  const service: WebvhService[] = [...didCommService, ...mimiService]

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
    ...(input.alsoKnownAs?.length ? { alsoKnownAs: input.alsoKnownAs } : {}),
    ...(input.name ? { name: input.name } : {}),
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

/** Same transform as `didToRoutingUrl`, but from a bare domain -- no SCID
 * needed, mirroring `domainDidJsonlUrl` in identifier.ts. What the mail
 * plugin bridge uses (mediator/mail-plugin/bridge.ts): an inbound
 * address's did:webvh<->mail mapping is already public (the whole reason
 * the earlier VC-based design was dropped, 2026-08-30), so there is
 * nothing to gain from resolving the full signed did:webvh log just to
 * reach the same routing.json a domain-only GET already serves. */
export function domainRoutingJsonUrl(domain: string, port?: number): string {
  const hostname = new URL(`https://${domain}`).hostname
  const hostPart = port ? `${hostname}:${port}` : hostname
  return `https://${hostPart}/.well-known/routing.json`
}

/** `fetchRouting`'s domain-only counterpart. */
export async function fetchRoutingByDomain(domain: string, fetchImpl: typeof fetch, port?: number): Promise<RoutingDoc | null> {
  const resp = await fetchImpl(domainRoutingJsonUrl(domain, port))
  if (resp.status === 404) return null
  if (!resp.ok) throw new Error(`fetchRoutingByDomain: GET failed with HTTP ${resp.status}`)
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

/** Sets the self-asserted display name, preserving everything else already
 * in routing.json (service/keyAgreement/mlkem/alsoKnownAs) -- a fetch-modify-
 * put on the JSON directly rather than going through buildRoutingDoc, which
 * would need the raw key material re-derived from what's already-published
 * multibase-encoded verification methods to rebuild them from scratch, for
 * no benefit here. Throws (rather than silently creating a bare routing.json
 * with just a name) when this identity hasn't published one yet -- that only
 * happens via enableDidComm, which main.ts runs automatically at boot
 * whenever a core is configured, so this should be reachable in practice
 * only after that has already run at least once. */
export async function setRoutingName(
  did: string, name: string, signing: { updateKey: string; privateKey: Uint8Array }, fetchImpl: typeof fetch,
): Promise<void> {
  const current = await fetchRouting(did, fetchImpl)
  if (!current) throw new Error('setRoutingName: this identity has no routing.json to update yet')
  await putRouting(did, { ...current, name }, signing, fetchImpl)
}
