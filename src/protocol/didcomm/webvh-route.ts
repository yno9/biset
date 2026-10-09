// Picks a DIDComm route out of an already-resolved did:webvh document.
//
// Replaces webvh-routing.ts (deleted 2026-09-16 with routing.json itself):
// `keyAgreement` and the `#didcomm` DIDCommMessaging service now live in the
// signed did:webvh log, published by did.md Wallet's
// `urn:did-core:document-edit:v1`, so there is nothing to merge in from a
// second document. Verified live against
// `cb81.did.md/.well-known/did.jsonl`: `keyAgreement` is an array of
// `#k_<id>` FRAGMENT REFERENCES (not embedded verification methods), each
// resolving to a `Multikey` X25519 entry in `verificationMethod`, and
// `service[#didcomm].serviceEndpoint` carries `{uri, accept, routingKeys}`
// with the mediator's did:peer in `routingKeys`.
//
// One function, two callers -- client/didcomm/front-door-send.ts (outbound
// DIDComm) and server/mediator/mail-plugin/bridge.ts (SMTP RCPT TO
// resolution). They used to each unpack the routing document their own way;
// a divergence there means mail silently routes to a different device than
// chat does.
import type { WebvhDidDocument } from '../webvh/document.ts'
import { selectDidCommEndpoint } from './service-endpoint.ts'
import { decodeKeyAgreementMultikey, keyAgreementKeyFromJwk } from './key-agreement.ts'
import type { X25519Recipient } from './crypto.ts'

interface DidCommServiceEndpoint extends Record<string, unknown> {
  uri: string
  accept: string[]
  routingKeys: string[]
}

export interface DidCommRoute {
  endpoint?: Partial<DidCommServiceEndpoint>
  /** Every keyAgreement key of the DID -- one per device. A sender encrypts
   * one message to all of them (DIDComm v2.1: "all keys declared in the
   * keyAgreement section ... are used as target keys"), so whichever of the
   * recipient's devices picks it up can open it. */
  recipients: X25519Recipient[]
}

/** The key-agreement keys a DID document lists under `keyAgreement`, with
 * absolute kids and their curve (X25519, P-256, P-384: key-agreement.ts). `keyAgreement`
 * holds references, so an entry counts only if it dereferences to a
 * verificationMethod (matched on the absolute DID URL and on the bare
 * `#fragment`, since a document may store either form) whose `Multikey` or
 * `publicKeyJwk` decodes as one of those; anything else is skipped. Shared by
 * did:webvh and did:web resolution. */
export function keyAgreementRecipients(doc: { id: string; keyAgreement?: string[]; verificationMethod?: Array<{ id: string; publicKeyMultibase?: string; publicKeyJwk?: Record<string, unknown> }> }): X25519Recipient[] {
  const absolute = (id: string) => id.startsWith('#') ? `${doc.id}${id}` : id
  const wanted = new Set((doc.keyAgreement ?? []).map(absolute))
  const recipients: X25519Recipient[] = []
  for (const vm of doc.verificationMethod ?? []) {
    const kid = absolute(vm.id)
    if (!wanted.has(kid) || recipients.some(r => r.kid === kid)) continue
    try {
      const key = typeof vm.publicKeyMultibase === 'string' ? decodeKeyAgreementMultikey(vm.publicKeyMultibase) : keyAgreementKeyFromJwk(vm.publicKeyJwk ?? {})
      recipients.push({ kid, publicKey: key.publicKey, ...(key.curve === 'X25519' ? {} : { curve: key.curve }) })
    } catch { /* not a key-agreement key */ }
  }
  return recipients
}

/** The live DIDCommMessaging service is the newest one in the document. */
export function didCommRouteFromDocument(doc: WebvhDidDocument, options: { preferOnion?: boolean } = {}): DidCommRoute {
  const service = [...doc.service].reverse().find(value => value.type === 'DIDCommMessaging')
  // A mediator with a Tor entrance publishes a set (PLAN-tor.md D-4);
  // `preferOnion` is set only by a sender that is itself on Tor (D-5/D-6).
  const endpoint = selectDidCommEndpoint(service?.serviceEndpoint, options.preferOnion) as Partial<DidCommServiceEndpoint> | undefined
  return { endpoint, recipients: keyAgreementRecipients(doc) }
}
