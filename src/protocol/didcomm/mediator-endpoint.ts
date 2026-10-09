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
import { decodePeerDid2, peerKeyAgreementRecipients } from './peer.ts'
import { resolveDidWeb, didWebDidCommRoute } from './did-web.ts'
import { peerHop, type ForwardHop } from './forward-wrap.ts'

export interface ExpandedEndpoint {
  /** Where to POST. */
  url: string
  /** Who to wrap Forwards for, outermost (closest to the sender) first. Empty
   * for an endpoint that is a plain URL with no routingKeys: deliver directly. */
  hops: ForwardHop[]
}

/** A hop named by a routing key (a DID URL, DIDComm v2.1): a did:peer:2 kid
 * carries its key; a did:web kid (what a document published after the mediator
 * became a did:web carries) is read from that DID's document. */
async function routingHop(kid: string, fetchImpl: typeof fetch): Promise<ForwardHop> {
  if (kid.startsWith('did:peer:2.')) return peerHop(kid)
  if (!kid.startsWith('did:web:') || !kid.includes('#')) throw new Error(`routing key ${kid}: only did:peer:2 and did:web keys are supported`)
  const did = kid.slice(0, kid.indexOf('#'))
  const doc = await resolveDidWeb(did, fetchImpl)
  if (!doc) throw new Error(`routing key ${kid}: ${did} does not resolve`)
  const fragment = kid.slice(kid.indexOf('#'))
  const key = keyAgreementRecipients(doc).find(recipient => recipient.kid.slice(recipient.kid.indexOf('#')) === fragment)
  if (!key) throw new Error(`routing key ${kid} is not a keyAgreement key of ${did}`)
  return { kid, recipients: [key] }
}

export async function expandEndpoint(
  endpoint: { uri: string; routingKeys?: readonly string[] },
  fetchImpl: typeof fetch,
  options: { preferOnion?: boolean } = {},
): Promise<ExpandedEndpoint> {
  const routingHops = await Promise.all((endpoint.routingKeys ?? []).map(kid => routingHop(kid, fetchImpl)))
  if (!endpoint.uri.startsWith('did:')) {
    return { url: endpoint.uri, hops: routingHops }
  }
  const mediator = await resolveMediator(endpoint.uri, fetchImpl, options)
  return { url: mediator.url, hops: [mediator.hop, ...routingHops] }
}

interface ResolvedMediator { url: string; hop: ForwardHop }

async function resolveMediator(did: string, fetchImpl: typeof fetch, options: { preferOnion?: boolean }): Promise<ResolvedMediator> {
  if (did.startsWith('did:peer:2.')) {
    const doc = decodePeerDid2(did)
    const kid = doc.keyAgreement[0]
    const endpoint = doc.service[0]?.serviceEndpoint
    if (!kid || !endpoint?.uri) throw new Error(`mediator ${did} has no key or no DIDComm endpoint`)
    if (endpoint.uri.startsWith('did:') || endpoint.routing_keys.length > 0) throw new Error(`mediator ${did} must name a plain URL as its own endpoint`)
    return { url: endpoint.uri, hop: { kid, recipients: peerKeyAgreementRecipients(doc) } }
  }
  if (!did.startsWith('did:web:')) throw new Error(`mediator ${did}: only did:web and did:peer mediators are supported`)
  const doc = await resolveDidWeb(did, fetchImpl)
  if (!doc) throw new Error(`mediator ${did} does not resolve`)
  const route = didWebDidCommRoute(doc, options)
  if (route.uri.startsWith('did:') || route.routingKeys.length > 0) throw new Error(`mediator ${did} must name a plain URL, with no routingKeys of its own, as its endpoint`)
  const recipients = keyAgreementRecipients(doc)
  return { url: route.uri, hop: { kid: recipients[0]!.kid, recipients } }
}
