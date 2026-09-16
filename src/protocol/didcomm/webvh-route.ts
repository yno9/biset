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
import type { WebvhDidDocument, WebvhVerificationMethod } from '../webvh/document.ts'

interface DidCommServiceEndpoint extends Record<string, unknown> {
  uri: string
  accept: string[]
  routingKeys: string[]
}

export interface DidCommRoute {
  endpoint?: Partial<DidCommServiceEndpoint>
  keyAgreement?: WebvhVerificationMethod
}

/** Wallet enrollment appends a new public front-door device rather than
 * rewriting older (possibly offline) device entries, so the NEWEST
 * DIDCommMessaging service and keyAgreement entry are the live ones.
 *
 * `#didcomm-biset-<suffix>` (config.json's `previousIds`) links a service to
 * one specific device key by suffix; the current `#didcomm` form does not,
 * and falls back to the newest keyAgreement entry. Both are handled here so
 * a document written before and after that rename resolves identically. */
export function didCommRouteFromDocument(doc: WebvhDidDocument): DidCommRoute {
  const service = [...doc.service].reverse().find(value => value.type === 'DIDCommMessaging')
  const serviceEndpoint = service?.serviceEndpoint
  const endpoint = serviceEndpoint && typeof serviceEndpoint === 'object' && !Array.isArray(serviceEndpoint)
    ? serviceEndpoint as Partial<DidCommServiceEndpoint>
    : undefined
  // `keyAgreement` holds references, so an entry is only usable if it
  // dereferences to a verificationMethod -- matched on the absolute DID URL
  // and on the bare `#fragment`, since a document may store either form.
  const keyAgreementIds = new Set(doc.keyAgreement ?? [])
  const isKeyAgreement = (vm: WebvhVerificationMethod): boolean =>
    keyAgreementIds.has(vm.id) || keyAgreementIds.has(vm.id.startsWith('#') ? `${doc.id}${vm.id}` : `#${vm.id.split('#', 2)[1] ?? ''}`)
  const suffix = /#didcomm-biset-([A-Za-z0-9_-]+)$/.exec(service?.id ?? '')?.[1]
  const bound = suffix
    ? doc.verificationMethod.find(vm => vm.id.endsWith(`#k_${suffix}`) && isKeyAgreement(vm))
    : undefined
  return { endpoint, keyAgreement: bound ?? [...doc.verificationMethod].reverse().find(isKeyAgreement) }
}

/** A DID Document may store a key id as `#fragment`, but a DIDComm JWE
 * header travels outside that document and must carry the absolute DID
 * URL. */
export function absoluteKid(doc: WebvhDidDocument, kid: string): string {
  return kid.startsWith('#') ? `${doc.id}${kid}` : kid
}
