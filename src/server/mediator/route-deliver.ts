// Packs a plaintext for every key of one recipient DID and, when a mediator hop chain is
// published, Forward-wraps it -- the "where does this actually go" half of
// send-message.ts's sendFrontDoorMessage, factored out so the mail plugin
// bridge (mediator/mail-plugin/bridge.ts) can reuse the exact same
// packaging logic against a domain-resolved DID document instead of a full
// did:webvh document.
import { packAuthcrypt, packAnoncrypt, type DidCommJWE, type X25519Recipient } from '../../protocol/didcomm/crypto.ts'
import { wrapForwardChain } from '../../protocol/didcomm/forward-wrap.ts'

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
 * to `recipientDid` through `endpoint.routingKeys`; absent or empty
 * `routingKeys` means direct delivery to `endpoint.uri`, no Forward. */
export function packForDelivery(
  plaintextBytes: Uint8Array,
  sender: { kid: string; privateKey: Uint8Array } | undefined,
  recipientDid: string,
  recipients: readonly X25519Recipient[],
  endpoint: RouteEndpoint,
): OutboundDelivery {
  const jwe = sender ? packAuthcrypt(plaintextBytes, sender, recipients) : packAnoncrypt(plaintextBytes, recipients)
  const routingKeys = endpoint.routingKeys ?? []
  const outbound = routingKeys.length > 0 ? wrapForwardChain(jwe, recipientDid, routingKeys) : jwe
  return { postUrl: endpoint.uri, outbound }
}
