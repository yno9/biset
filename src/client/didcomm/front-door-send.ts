// The Vault-independent half of send-message.ts's outbound DIDComm send:
// resolve the recipient's did:webvh document, authcrypt (Forward-wrapped through a registered
// mediator when the recipient has one), POST. Split out (2026-08-31) so
// DOM-less deploy units (mls-ds/, whose own tsconfig has no `lib: ["DOM"]`)
// that need only this generic primitive stay free of the client's Vault and
// UI code (tsconfig.mediator.json's own header explains why: proving a
// deploy unit stays free of Vault/UI coupling is the whole point of the
// DOM-less check). send-message.ts builds chat messages on it.
import { resolve } from '../../protocol/webvh/resolver.ts'
import { didCommPost, packAuthcrypt, type DidCommJWE, type X25519Recipient } from '../../protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../../protocol/didcomm/message.ts'
import { wrapForwardHops, type ForwardHop } from '../../protocol/didcomm/forward-wrap.ts'
import { expandEndpoint } from '../../protocol/didcomm/mediator-endpoint.ts'
import { decodePeerDid2, publicKeyOf } from '../../protocol/didcomm/peer.ts'
import { didCommRouteFromDocument } from '../../protocol/didcomm/webvh-route.ts'
import { defaultFetch } from '../../protocol/net-fetch.ts'
import { isTorEnvironment } from './mediator-endpoints.ts'
import { resolveDidWeb, didWebDidCommRoute } from '../../protocol/didcomm/did-web.ts'

/** A did:peer:2 counterpart -- a mediator, or another device/bot addressed
 * directly by its did:peer rather than a did:webvh identity (e.g. a service
 * with no domain of its own to publish a did:webvh log at). Self-certifying:
 * everything `resolveFrontDoorRoute` needs is IN the DID string, no network
 * call. Distinguishing it from did:webvh up front (rather than letting
 * `resolve` fail on it) is what makes a did:peer recipient a
 * valid `sendFrontDoorMessage` target at all -- found
 * live 2026-09-09: an outside DIDComm agent identified only by a did:peer
 * (no domain to host a did:webvh log at) could not receive a first-contact
 * message otherwise (`parseWebvhDid: not a did:webvh identifier`). */
function isDidPeer(did: string): boolean {
  return did.startsWith('did:peer:2.')
}

interface FrontDoorRoute {
  /** Every keyAgreement key of the recipient DID -- one per device. */
  recipients: X25519Recipient[]
  /** Where to POST: the recipient's own endpoint, or its mediator's. */
  endpointUri: string
  /** The mediators to wrap Forwards for, outermost first; none means deliver directly. */
  hops: ForwardHop[]
}

/** Resolves a recipient's DIDComm route regardless of DID method: did:peer:2
 * decodes locally (self-certifying); did:web and did:webvh resolve over the
 * network (`resolve` + `didCommRouteFromDocument`). The endpoint it names --
 * a URL, or the DID of the recipient's mediator -- is then expanded into where
 * to POST and whom to wrap for (`expandEndpoint`). Shared by
 * `sendFrontDoorMessage` so the DID-method split
 * lives in exactly one place. */
async function resolveFrontDoorRoute(toDid: string, fetchImpl: typeof fetch): Promise<FrontDoorRoute> {
  const preferOnion = isTorEnvironment()
  let recipients: X25519Recipient[]
  let endpoint: { uri: string; routingKeys: string[] }

  if (isDidPeer(toDid)) {
    const doc = decodePeerDid2(toDid)
    if (doc.keyAgreement.length === 0) throw new Error(`${toDid} has no keyAgreement key published`)
    const published = doc.service[0]?.serviceEndpoint
    if (!published?.uri) throw new Error(`${toDid} has no DIDComm service endpoint published`)
    recipients = doc.keyAgreement.map(kid => ({ kid, publicKey: publicKeyOf(doc, kid) }))
    endpoint = { uri: published.uri, routingKeys: published.routing_keys ?? [] }
  } else if (toDid.startsWith('did:web:')) {
    const doc = await resolveDidWeb(toDid, fetchImpl)
    if (!doc) throw new Error(`${toDid} does not resolve to a published identity`)
    const route = didWebDidCommRoute(doc)
    recipients = route.recipients
    endpoint = { uri: route.uri, routingKeys: route.routingKeys }
  } else {
    const doc = await resolve(toDid, undefined, fetchImpl)
    if (!doc) throw new Error(`${toDid} does not resolve to a published identity`)
    // PLAN-tor.md D-5/D-6: dial the recipient's onion entrance only when this page is itself served over Tor.
    const route = didCommRouteFromDocument(doc, { preferOnion })
    if (!route.endpoint?.uri) throw new Error(`${toDid} has no DIDComm service endpoint published`)
    if (route.recipients.length === 0) throw new Error(`${toDid} has no keyAgreement key published -- they need to enable DIDComm first`)
    recipients = route.recipients
    endpoint = { uri: route.endpoint.uri, routingKeys: route.endpoint.routingKeys ?? [] }
  }

  const expanded = await expandEndpoint(endpoint, fetchImpl, { preferOnion })
  return { recipients, endpointUri: expanded.url, hops: expanded.hops }
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
  id?: string
  /** The `created_time` header, epoch seconds. Defaults to now. */
  createdTime?: number
  /** The plaintext `to` (the audience) when it is more than the recipient:
   * a group message lists every participant. Defaults to `[toDid]`. */
  audience?: readonly string[]
  thid?: string
  /** DID Rotation: sent from a DID this identity rotated to, until the
   * recipient has written to it (from-prior.ts). */
  fromPrior?: string
  attachments?: Array<{ id: string; media_type?: string; data: { json?: unknown; base64?: string } }>
}

/** The generic "resolve the recipient, authcrypt (Forward-wrapped if the
 * recipient registered a mediator), POST" primitive `sendDidCommMessage`
 * (send-message.ts) is a thin wrapper around --
 * exported so a caller needing an arbitrary `type`/`body`
 * (mls-ds/fanout.ts's `message-notify` delivery, mls-ds-1.0.md §5.2)
 * doesn't have to reimplement route resolution and Forward-wrapping
 * to get one. */
export async function sendFrontDoorMessage(toDid: string, type: string, body: unknown, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  let route: FrontDoorRoute
  try {
    route = await resolveFrontDoorRoute(toDid, fetchImpl)
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }

  const plaintext = buildPlaintext(type, body, opts.fromKid.split('#', 1)[0], opts.audience ?? toDid, { id: opts.id, createdTime: opts.createdTime, thid: opts.thid, attachments: opts.attachments, fromPrior: opts.fromPrior })
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext))
  const sender = { kid: opts.fromKid, privateKey: opts.x25519PrivateKey }

  // One JWE for every device of the recipient (multiplexed encryption).
  const jwe = packAuthcrypt(plaintextBytes, sender, route.recipients)

  // Any hop means the recipient has registered with an independent, blind
  // mediator (named by DID, or by URL plus did:peer routing keys): deliver
  // Forward-wrapped through it rather than authcrypt'ing straight to
  // `endpointUri` (the legacy first-party-infra model, still supported for a
  // did:webvh identity that hasn't migrated yet -- always at least one hop
  // for a did:peer:2 recipient, which is only ever reachable through its own
  // mediator). The hops are a chain (forward-wrap.ts's `wrapForwardHops`,
  // outermost/closest-to-sender first).
  const outbound: DidCommJWE = route.hops.length > 0 ? wrapForwardHops(jwe, toDid, route.hops) : jwe
  const response = await fetchImpl(route.endpointUri, didCommPost(outbound))
  if (response.status !== 202) {
    return { ok: false, error: `send failed: HTTP ${response.status} ${(await response.text().catch(() => '')).slice(0, 256)}` }
  }
  return { ok: true }
}
