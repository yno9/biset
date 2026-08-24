// Splices routing.json's keyAgreement/service into a document resolved from
// the signed did:webvh log alone — identity/webvh/resolver.ts's own resolve()
// deliberately returns an empty `service`/no `keyAgreement` (that module's
// header: "wrong for anything that needs DIDComm routing data"). This is the
// DIDComm-side counterpart that actually needs it, kept out of resolver.ts
// itself so the core identity resolver stays free of DIDComm concerns.
//
// Ported from src.bak/did/webvh/resolver.ts's mergeRouting.
import { resolve } from '../identity/webvh/resolver.ts'
import type { WebvhDidDocument } from '../identity/webvh/document.ts'
import { defaultFetch } from '../net-fetch.ts'
import { fetchRouting, type RoutingDoc } from './webvh-routing.ts'

/** `routing === null` means "no routing.json exists for this identity" —
 * this identity simply hasn't provisioned a DIDComm-capable device yet.
 * Returns `doc` untouched in that case (nothing to add). */
export function mergeRouting(doc: WebvhDidDocument, routing: RoutingDoc | null): WebvhDidDocument {
  if (!routing) return doc
  const kaVms = routing.keyAgreementVerificationMethod ?? []
  const mlkemVms = routing.mlkemVerificationMethod ?? []
  return {
    ...doc,
    verificationMethod: [...doc.verificationMethod, ...kaVms, ...mlkemVms],
    ...(kaVms.length ? { keyAgreement: kaVms.map(vm => vm.id) } : {}),
    // Concatenated, not replaced: `doc.service` from the signed log is just
    // the one constant `#routing` pointer entry (webvh-routing-pointer.ts) —
    // routing.json's own entries add to it rather than overwriting it, so
    // that pointer survives every resolve instead of being wiped out by the
    // same merge that's supposed to be adding MORE service info.
    service: [...doc.service, ...routing.service],
  }
}

/** resolve() (the signed log alone) + routing.json, merged. What a DIDComm
 * sender actually needs: a keyAgreement key and a DIDCommMessaging service
 * endpoint to address this identity. */
export async function resolveWithRouting(did: string, fetchImpl: typeof fetch = defaultFetch()): Promise<WebvhDidDocument | null> {
  const doc = await resolve(did)
  if (!doc) return null
  const routing = await fetchRouting(did, fetchImpl)
  return mergeRouting(doc, routing)
}
