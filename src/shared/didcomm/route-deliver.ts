// Packs a plaintext for one recipient kid and, when a mediator hop chain is
// published, Forward-wraps it -- the "where does this actually go" half of
// send-message.ts's sendFrontDoorMessage, factored out so the mail plugin
// bridge (mediator/mail-plugin/bridge.ts) can reuse the exact same
// packaging logic against a domain-resolved routing.json instead of a full
// did:webvh document.
import { packAuthcrypt, packAnoncrypt, type DidCommJWE } from './crypto.ts'
import { wrapForwardChain } from './forward-wrap.ts'

export interface RouteEndpoint {
  uri: string
  routingKeys?: string[]
}

export interface OutboundDelivery {
  postUrl: string
  outbound: DidCommJWE
}

/** `sender` is omitted for anoncrypt (no DIDComm-level sender identity to
 * assert -- e.g. genuinely unauthenticated inbound SMTP). `routingKeys`
 * absent or empty means direct delivery to `endpoint.uri`, no Forward. */
export function packForDelivery(
  plaintextBytes: Uint8Array,
  sender: { kid: string; privateKey: Uint8Array } | undefined,
  recipientKid: string,
  recipientPublicKey: Uint8Array,
  endpoint: RouteEndpoint,
): OutboundDelivery {
  const jwe = sender
    ? packAuthcrypt(plaintextBytes, sender, { kid: recipientKid, publicKey: recipientPublicKey })
    : packAnoncrypt(plaintextBytes, { kid: recipientKid, publicKey: recipientPublicKey })
  const routingKeys = endpoint.routingKeys ?? []
  const outbound = routingKeys.length > 0 ? wrapForwardChain(jwe, recipientKid, routingKeys) : jwe
  return { postUrl: endpoint.uri, outbound }
}
