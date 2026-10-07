// A DIDComm service endpoint turned into where to POST and whom to wrap for.
//
// A service endpoint's `uri` is a URL -- or, when the recipient sits behind a
// mediator, the mediator's DID (DIDComm Messaging v2.1, "Using a DID as an
// endpoint"). That DID is resolved: its `DIDCommMessaging` service gives the
// URL, and its keyAgreement keys are implicitly PREPENDED to the endpoint's own
// `routingKeys` -- they are the first hop. The point of naming the mediator by
// DID is that it can rotate its keys or move its URL without every recipient's
// DID document being rewritten.
//
// Per the spec the mediator's own document uses a plain URL (no DID, so no
// recursion), and here also no routingKeys of its own.
import { keyAgreementRecipients } from './webvh-route.ts'
import { decodePeerDid2, publicKeyOf } from './peer.ts'
import { resolveDidWeb, didWebDidCommRoute } from './did-web.ts'
import { peerHop, type ForwardHop } from './forward-wrap.ts'

export interface ExpandedEndpoint {
  /** Where to POST. */
  url: string
  /** Who to wrap Forwards for, outermost (closest to the sender) first. Empty
   * for an endpoint that is a plain URL with no routingKeys: deliver directly. */
  hops: ForwardHop[]
  /** The did:peer:2 kid of the first hop's key, when it has one -- what a
   * private did:peer relationship embeds as its mediator (relationship.ts), as
   * it must not depend on resolving anything. A mediator named by did:web
   * publishes its did:peer as an `alsoKnownAs` alias. */
  peerKid?: string
}

export async function expandEndpoint(
  endpoint: { uri: string; routingKeys?: readonly string[] },
  fetchImpl: typeof fetch,
  options: { preferOnion?: boolean } = {},
): Promise<ExpandedEndpoint> {
  const routingHops = (endpoint.routingKeys ?? []).map(peerHop)
  if (!endpoint.uri.startsWith('did:')) {
    return { url: endpoint.uri, hops: routingHops, ...(routingHops[0] ? { peerKid: routingHops[0].kid } : {}) }
  }
  const mediator = await resolveMediator(endpoint.uri, fetchImpl, options)
  return { url: mediator.url, hops: [mediator.hop, ...routingHops], ...(mediator.peerKid ? { peerKid: mediator.peerKid } : {}) }
}

interface ResolvedMediator { url: string; hop: ForwardHop; peerKid?: string }

async function resolveMediator(did: string, fetchImpl: typeof fetch, options: { preferOnion?: boolean }): Promise<ResolvedMediator> {
  if (did.startsWith('did:peer:2.')) {
    const doc = decodePeerDid2(did)
    const kid = doc.keyAgreement[0]
    const endpoint = doc.service[0]?.serviceEndpoint
    if (!kid || !endpoint?.uri) throw new Error(`mediator ${did} has no key or no DIDComm endpoint`)
    if (endpoint.uri.startsWith('did:') || endpoint.routing_keys.length > 0) throw new Error(`mediator ${did} must name a plain URL as its own endpoint`)
    return { url: endpoint.uri, hop: { kid, recipients: doc.keyAgreement.map(k => ({ kid: k, publicKey: publicKeyOf(doc, k) })) }, peerKid: kid }
  }
  if (!did.startsWith('did:web:')) throw new Error(`mediator ${did}: only did:web and did:peer mediators are supported`)
  const doc = await resolveDidWeb(did, fetchImpl)
  if (!doc) throw new Error(`mediator ${did} does not resolve`)
  const route = didWebDidCommRoute(doc, options)
  if (route.uri.startsWith('did:') || route.routingKeys.length > 0) throw new Error(`mediator ${did} must name a plain URL, with no routingKeys of its own, as its endpoint`)
  const recipients = keyAgreementRecipients(doc)
  return { url: route.uri, hop: { kid: recipients[0]!.kid, recipients }, peerKid: peerAlias(doc, route.uri, recipients) }
}

/** The mediator's did:peer:2 alias -- one of its `alsoKnownAs` -- if it really
 * is the same mediator: its key is one of the document's own keyAgreement
 * keys, and its endpoint is the document's URL. Anything else is ignored. */
function peerAlias(doc: { alsoKnownAs?: string[] }, url: string, recipients: readonly { publicKey: Uint8Array }[]): string | undefined {
  for (const alias of doc.alsoKnownAs ?? []) {
    if (!alias.startsWith('did:peer:2.')) continue
    try {
      const peer = decodePeerDid2(alias)
      const kid = peer.keyAgreement[0]
      if (!kid || peer.service[0]?.serviceEndpoint.uri !== url) continue
      const key = publicKeyOf(peer, kid)
      if (recipients.some(recipient => recipient.publicKey.length === key.length && recipient.publicKey.every((byte, i) => byte === key[i]))) return kid
    } catch { /* not a usable alias */ }
  }
  return undefined
}
