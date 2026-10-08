// Packs a plaintext for every key of one recipient DID and, when a mediator hop chain is
// published, Forward-wraps it -- the "where does this actually go" half of
// send-message.ts's sendFrontDoorMessage, factored out so the mail plugin
// bridge (mediator/mail-plugin/bridge.ts) can reuse the exact same
// packaging logic against a domain-resolved DID document instead of a full
// did:webvh document.
import { packAuthcrypt, packAnoncrypt, type DidCommJWE, type X25519Recipient } from '../../protocol/didcomm/crypto.ts'
import { wrapForwardHops } from '../../protocol/didcomm/forward-wrap.ts'
import { expandEndpoint } from '../../protocol/didcomm/mediator-endpoint.ts'

export interface RouteEndpoint {
  uri: string
  routingKeys?: string[]
}

export interface OutboundDelivery {
  postUrl: string
  outbound: DidCommJWE
}

/** `sender` is omitted for anoncrypt (no DIDComm-level sender identity to
 * assert -- e.g. genuinely unauthenticated inbound SMTP). One JWE for every
 * key in `recipients` (all of the recipient DID's devices), Forward-wrapped
 * to `recipientDid` through the endpoint's hops. The endpoint is expanded the
 * way every sender does (expandEndpoint): its `uri` is a URL or a mediator's
 * DID, and its `routingKeys` are did:peer or did:web keys. No hops means
 * direct delivery to the URL, no Forward. */
export async function packForDelivery(
  plaintextBytes: Uint8Array,
  sender: { kid: string; privateKey: Uint8Array } | undefined,
  recipientDid: string,
  recipients: readonly X25519Recipient[],
  endpoint: RouteEndpoint,
  fetchImpl: typeof fetch = fetch,
): Promise<OutboundDelivery> {
  const jwe = sender ? packAuthcrypt(plaintextBytes, sender, recipients) : packAnoncrypt(plaintextBytes, recipients)
  const expanded = await expandEndpoint({ uri: endpoint.uri, routingKeys: endpoint.routingKeys ?? [] }, fetchImpl)
  const outbound = expanded.hops.length > 0 ? wrapForwardHops(jwe, recipientDid, expanded.hops) : jwe
  return { postUrl: expanded.url, outbound }
}
