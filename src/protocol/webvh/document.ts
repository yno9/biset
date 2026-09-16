// The W3C DID Core JSON shape a did:webvh log entry's `state` field carries
// directly. Read-only subset: only the fields this resolver actually
// produces or consumes. biset's full document builder (
// keyAgreement/service assembly) stays in `src.bak/did/webvh/document.ts`
// until the write path is ported.
import { encodeMultikey } from './multikey.ts'

export interface WebvhVerificationMethod {
  id: string
  type: 'Multikey'
  controller: string
  publicKeyMultibase: string
}

interface WebvhService {
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
 * WebvhDidDocument only in `alsoKnownAs`, which biset itself never writes
 * (did.md uses it for DID aliases). `keyAgreement`/`service`/`name` ARE
 * carried by the signed log — that is where they live since routing.json
 * was retired (2026-09-16). */
export type SignedWebvhState = Omit<WebvhDidDocument, 'alsoKnownAs'>

/** Builds the minimal signed genesis/update state: `id` and the one root key
 * that defines this identity. Nothing else — no service entries, since
 * identity generation publishes no DIDComm data; did.md Wallet appends the
 * device keys and `#didcomm` service afterwards. */
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
