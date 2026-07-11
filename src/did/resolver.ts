// Thin resolution seam (DID.md: "the only method-abstraction — multi-method
// support is YAGNI"). No other code may assume a resolution mechanism; every
// caller goes through resolve(). The body is Phase 2 (gateway/Pkarr required,
// browsers can't speak DHT directly) — Phase 1 only fixes the interface.
export interface DidServiceEndpoint {
  id: string
  type: string
  serviceEndpoint: string
}

export interface DidDocument {
  id: string // the did:dht:... string
  alsoKnownAs?: string[] // current address(es), e.g. ["mailto:dab0@non.md"]
  verificationMethod: Array<{ id: string; type: string; publicKeyMultibase?: string }>
  service?: DidServiceEndpoint[]
}

export async function resolve(_did: string): Promise<DidDocument> {
  throw new Error('DID resolution requires a Pkarr gateway — not implemented until Phase 2')
}
