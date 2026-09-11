// The Vault-independent half of send-message.ts's outbound DIDComm send:
// resolve routing.json, authcrypt (Forward-wrapped through a registered
// mediator when the recipient has one), POST. Split out (2026-08-31) so
// DOM-less deploy units (mls-ds/, whose own tsconfig has no `lib: ["DOM"]`)
// that need only this generic primitive don't pull in send-message.ts's
// relationship functions -- those depend on vault/contact-key.ts, which
// transitively reaches vault/objects.ts's Web Crypto `KeyUsage` type,
// unavailable without the DOM lib these deploy units deliberately exclude
// (tsconfig.mediator.json's own header explains why: proving a deploy unit
// stays free of Vault/UI coupling is the whole point of the DOM-less check).
// send-message.ts re-exports this unchanged for its own existing callers.
import { resolveWithRouting } from '../../protocol/didcomm/webvh-resolve.ts'
import { decodeX25519Multikey, decodeMlkem768Multikey } from '../../protocol/didcomm/multikey.ts'
import { packAuthcrypt, packAuthcryptHybrid, type DidCommJWE } from '../../protocol/didcomm/crypto.ts'
import { mlkemKidFor } from '../../protocol/didcomm/devicekid.ts'
import { buildPlaintext } from '../../protocol/didcomm/message.ts'
import { wrapForwardChain } from '../../protocol/didcomm/forward-wrap.ts'
import { decodePeerDid2, publicKeyOf } from '../../protocol/didcomm/peer.ts'
import type { DidCommServiceEndpoint } from '../../protocol/didcomm/webvh-routing.ts'
import { defaultFetch } from '../../protocol/net-fetch.ts'

/** A did:peer:2 counterpart -- a mediator, or another device/bot addressed
 * directly by its did:peer rather than a did:webvh identity (e.g. a service
 * with no domain of its own to publish routing.json at). Self-certifying:
 * everything `resolveFrontDoorRoute` needs is IN the DID string, no network
 * call. Distinguishing it from did:webvh up front (rather than letting
 * `resolveWithRouting` fail on it) is what makes a did:peer recipient a
 * valid `sendFrontDoorMessage`/`initiateRelationship` target at all -- found
 * live 2026-09-09: an outside DIDComm agent identified only by a did:peer
 * (no domain to host did:webvh at) could not receive a first-contact
 * message otherwise (`parseWebvhDid: not a did:webvh identifier`). */
function isDidPeer(did: string): boolean {
  return did.startsWith('did:peer:2.')
}

interface FrontDoorRoute {
  publicKey: Uint8Array
  /** did:webvh recipients that also published an ML-KEM-768 entry alongside
   * their X25519 one (mlkemKidFor's naming convention) -- undefined for a
   * did:peer:2 recipient, which never publishes one in this codebase. */
  mlkemPublicKey?: Uint8Array
  keyAgreementKid: string
  endpointUri: string
  routingKeys: string[]
}

/** Resolves a recipient's DIDComm route regardless of DID method: did:peer:2
 * decodes locally (self-certifying); did:webvh resolves the signed log +
 * routing.json over the network (`resolveWithRouting`). Shared by
 * `sendFrontDoorMessage` and `frontDoorMediatorRoute` so the did:peer/
 * did:webvh split lives in exactly one place. */
async function resolveFrontDoorRoute(toDid: string, fetchImpl: typeof fetch): Promise<FrontDoorRoute> {
  if (isDidPeer(toDid)) {
    const doc = decodePeerDid2(toDid)
    const keyAgreementKid = doc.keyAgreement[0]
    if (!keyAgreementKid) throw new Error(`${toDid} has no keyAgreement key published`)
    const endpoint = doc.service[0]?.serviceEndpoint
    if (!endpoint?.uri) throw new Error(`${toDid} has no DIDComm service endpoint published`)
    return {
      publicKey: publicKeyOf(doc, keyAgreementKid),
      keyAgreementKid,
      endpointUri: endpoint.uri,
      routingKeys: endpoint.routing_keys ?? [],
    }
  }

  const doc = await resolveWithRouting(toDid, fetchImpl)
  if (!doc) throw new Error(`${toDid} does not resolve to a published identity`)
  const { endpoint, keyAgreement: kaVm } = newestDidCommRoute(doc)
  if (!endpoint?.uri) throw new Error(`${toDid} has no DIDComm service endpoint published`)
  if (!kaVm) throw new Error(`${toDid} has no keyAgreement key published -- they need to enable DIDComm first`)
  let mlkemPublicKey: Uint8Array | undefined
  try {
    const mlkemId = mlkemKidFor(kaVm.id)
    const mlkemVm = doc.verificationMethod.find(v => v.id === mlkemId)
    if (mlkemVm) mlkemPublicKey = decodeMlkem768Multikey(mlkemVm.publicKeyMultibase)
  } catch {
    mlkemPublicKey = undefined
  }
  return {
    publicKey: decodeX25519Multikey(kaVm.publicKeyMultibase),
    mlkemPublicKey,
    // A DID Document may store its key ID as `#fragment`, but DIDComm's JWE
    // header travels outside that document and must carry the absolute DID URL.
    keyAgreementKid: kaVm.id.startsWith('#') ? `${doc.id}${kaVm.id}` : kaVm.id,
    endpointUri: endpoint.uri,
    routingKeys: endpoint.routingKeys ?? [],
  }
}

export type DidCommSendResult = { ok: true } | { ok: false; error: string }

export interface SendDidCommMessageOptions {
  /** This device's own DIDComm kid (identity/bootstrap.ts's `enableDidComm`
   * -- didcomm/devicekid.ts's deviceKidFragment, distinct from the MLS
   * leaf's own deviceKid). */
  fromKid: string
  x25519PrivateKey: Uint8Array
  subject?: string
  fetch?: typeof fetch
}

/** Wallet enrollment appends a new public front-door device rather than
 * rewriting older (possibly offline) device entries. Prefer that newest
 * endpoint. Generic DIDComm documents still fall back to their newest
 * keyAgreement entry when no Biset device suffix links service and key. */
function newestDidCommRoute(doc: NonNullable<Awaited<ReturnType<typeof resolveWithRouting>>>) {
  const service = [...doc.service].reverse().find(value => value.type === 'DIDCommMessaging')
  const endpoint = service?.serviceEndpoint
  const value = endpoint && typeof endpoint === 'object' && !Array.isArray(endpoint)
    ? endpoint as Partial<DidCommServiceEndpoint>
    : undefined
  const keyAgreementIds = new Set(doc.keyAgreement ?? [])
  const suffix = /#didcomm-biset-([A-Za-z0-9_-]+)$/.exec(service?.id ?? '')?.[1]
  const keyAgreement = suffix
    ? doc.verificationMethod.find(candidate => candidate.id.endsWith(`#k_${suffix}`) && keyAgreementIds.has(candidate.id))
    : undefined
  return { endpoint: value, keyAgreement: keyAgreement ?? [...doc.verificationMethod].reverse().find(candidate => keyAgreementIds.has(candidate.id)) }
}

/** The generic "resolve routing.json, authcrypt (Forward-wrapped if the
 * recipient registered a mediator), POST" primitive `sendDidCommMessage`/
 * `initiateRelationship` (send-message.ts) are thin wrappers around --
 * exported so a caller needing an arbitrary `type`/`body`
 * (mls-ds/fanout.ts's `message-notify` delivery, mls-ds-1.0.md §5.2)
 * doesn't have to reimplement routing.json resolution and Forward-wrapping
 * to get one. */
export async function sendFrontDoorMessage(toDid: string, type: string, body: unknown, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  let route: FrontDoorRoute
  try {
    route = await resolveFrontDoorRoute(toDid, fetchImpl)
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }

  const plaintext = buildPlaintext(type, body, opts.fromKid.split('#', 1)[0], toDid)
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext))
  const sender = { kid: opts.fromKid, privateKey: opts.x25519PrivateKey }

  // Upgrade to the hybrid X25519+ML-KEM-768 authcrypt whenever the recipient
  // published an ML-KEM entry alongside their X25519 one -- this is the only
  // production path that ever reaches packAuthcryptHybrid; without it the
  // fully-implemented, tested PQ-hybrid mode was unreachable and every
  // message stayed exposed to harvest-now-decrypt-later even between two
  // devices that both supported it (found live, 2026-08-26).
  const jwe = route.mlkemPublicKey
    ? packAuthcryptHybrid(plaintextBytes, sender, {
        kid: route.keyAgreementKid,
        x25519PublicKey: route.publicKey,
        mlkemPublicKey: route.mlkemPublicKey,
      })
    : packAuthcrypt(plaintextBytes, sender, { kid: route.keyAgreementKid, publicKey: route.publicKey })

  // A non-empty routingKeys means the recipient has registered with an
  // independent, blind mediator: deliver Forward-wrapped through it rather
  // than authcrypt'ing straight to `endpointUri` (the legacy first-party-
  // infra model, still supported for a did:webvh identity that hasn't
  // migrated yet -- always non-empty for a did:peer:2 recipient, which is
  // only ever reachable through its own mediator). The full array is a hop
  // chain (forward-wrap.ts's `wrapForwardChain`, outermost/closest-to-sender
  // first) -- not just its first entry.
  let outbound: DidCommJWE = jwe
  if (route.routingKeys.length > 0) {
    try {
      outbound = wrapForwardChain(jwe, route.keyAgreementKid, route.routingKeys)
    } catch {
      return { ok: false, error: `${toDid}'s registered mediator routing keys (${route.routingKeys.join(', ')}) are not valid did:peer kids` }
    }
  }
  const response = await fetchImpl(route.endpointUri, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(outbound) })
  if (response.status !== 202) {
    return { ok: false, error: `send failed: HTTP ${response.status} ${(await response.text().catch(() => '')).slice(0, 256)}` }
  }
  return { ok: true }
}

/** Resolves a recipient's registered independent mediator route (url +
 * routing kid) -- send-message.ts's `initiateRelationship` uses this to
 * enroll a fresh private did:peer with the SAME mediator the recipient's
 * front door already advertises. */
export async function frontDoorMediatorRoute(toDid: string, fetchImpl: typeof fetch): Promise<{ url: string; routingKid: string }> {
  const route = await resolveFrontDoorRoute(toDid, fetchImpl)
  const routingKid = route.routingKeys[0]
  if (!routingKid) throw new Error(`${toDid} has no independent DIDComm mediator published`)
  // Decode before registration so a hostile routing document cannot make us
  // enroll a private key against a malformed/non-self-certifying route.
  publicKeyOf(decodePeerDid2(routingKid.split('#', 1)[0]!), routingKid)
  return { url: route.endpointUri, routingKid }
}
