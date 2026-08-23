// The W3C DID Core JSON shape a did:webvh log entry's `state` field carries
// directly. Read-only subset: only the fields this resolver actually
// produces or consumes. biset's full document builder (routing.json merge,
// keyAgreement/service assembly) stays in `src.bak/did/webvh/document.ts`
// until the write path is ported.
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
