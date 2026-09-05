// The W3C DID Core JSON shape a did:webvh log entry's `state` field carries
// directly. Read-only subset: only the fields this resolver actually
// produces or consumes. biset's full document builder (routing.json merge,
// keyAgreement/service assembly) stays in `src.bak/did/webvh/document.ts`
// until the write path is ported.
import { encodeMultikey } from './multikey.ts'

export interface WebvhVerificationMethod {
  id: string
  type: 'Multikey'
  controller: string
  publicKeyMultibase: string
}

export interface WebvhService {
  id: string
  type: string
  serviceEndpoint: string | string[] | Record<string, unknown>
}

export interface WebvhDidDocument {
  '@context': string[]
  id: string
  verificationMethod: WebvhVerificationMethod[]
  authentication: string[]
  keyAgreement?: string[]
  service: WebvhService[]
  alsoKnownAs: string[]
  name?: string
}

/** The signed log entry's own `state` shape — narrower than a resolved
 * WebvhDidDocument (no `alsoKnownAs`/`keyAgreement`/`name`/routing-derived
 * `service`: those are operational data Vault Core does not publish through
 * routing.json — see PLAN.md's identity-generation scope decision). */
export type SignedWebvhState = Omit<WebvhDidDocument, 'alsoKnownAs'>

/** Builds the minimal signed genesis/update state: `id` and the one root key
 * that defines this identity. Nothing else — no routing.json pointer, no
 * service entries — since Vault Core's identity generation does not publish
 * one (mail/DIDComm adapters will add whatever they need when they exist). */
export function buildMinimalWebvhState(did: string, rootPublicKey: Uint8Array): SignedWebvhState {
  const keyId = `${did}#key-1`
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [{ id: keyId, type: 'Multikey', controller: did, publicKeyMultibase: encodeMultikey(rootPublicKey) }],
    authentication: [keyId],
    service: [],
  }
}
