// Data Integrity Proof, eddsa-jcs-2022 cryptosuite (W3C VC Data Integrity /
// EdDSA Cryptosuites) — the only cryptosuite did:webvh v1.0 permits
// (DIDWEBVHFEAT.md §6). Hashes a "proof configuration" (everything about the
// proof except its signature) and the target document separately, concatenates
// the two hashes, and Ed25519-verifies the result.
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base58 } from '@scure/base'
import { canonicalize } from './jcs.ts'

export interface DataIntegrityProof {
  type: 'DataIntegrityProof'
  cryptosuite: 'eddsa-jcs-2022'
  created?: string
  proofPurpose: string
  verificationMethod: string
  proofValue: string
}

type ProofConfig = Omit<DataIntegrityProof, 'proofValue'>

function hashConfigAndDoc(config: ProofConfig, document: object): Uint8Array {
  const configHash = sha256(new TextEncoder().encode(canonicalize(config)))
  const docHash = sha256(new TextEncoder().encode(canonicalize(document)))
  const out = new Uint8Array(configHash.length + docHash.length)
  out.set(configHash, 0)
  out.set(docHash, configHash.length)
  return out
}

export function verifyProof(document: object, proof: DataIntegrityProof, publicKey: Uint8Array): boolean {
  if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022') return false
  if (!proof.proofValue.startsWith('z')) return false
  const { proofValue, ...config } = proof
  const signingInput = hashConfigAndDoc(config, document)
  let signature: Uint8Array
  try { signature = base58.decode(proofValue.slice(1)) } catch { return false }
  try { return ed25519.verify(signature, signingInput, publicKey) } catch { return false }
}
