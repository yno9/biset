// The W3C DID Core JSON shape a did:vh log entry's `state` field carries
// directly. Read-only subset: only the fields this resolver actually
// produces or consumes.
interface VhVerificationMethod {
  id: string
  type: 'Multikey'
  controller: string
  publicKeyMultibase: string
}

interface VhService {
  id: string
  type: string
  serviceEndpoint: string | Array<string | Record<string, unknown>> | Record<string, unknown>
}

export interface DidDocument {
  '@context': string[]
  id: string
  verificationMethod: VhVerificationMethod[]
  authentication: string[]
  keyAgreement?: string[]
  service: VhService[]
  alsoKnownAs: string[]
  name?: string
}
