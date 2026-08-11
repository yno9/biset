// Data Integrity Proof, eddsa-jcs-2022 cryptosuite (W3C VC Data Integrity /
// EdDSA Cryptosuites) — the only cryptosuite did:webvh v1.0 permits
// (DIDWEBVHFEAT.md §6). Hashes a "proof configuration" (everything about the
// proof except its signature) and the target document separately, concatenates
// the two hashes, and Ed25519-signs the result — the standard "hash then
// sign" shape every Data Integrity cryptosuite uses, specialized here to JCS
// canonicalization + SHA-256.
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

export function buildProof(
  document: object,
  opts: { verificationMethod: string; proofPurpose?: string; created?: string; privateKey: Uint8Array },
): DataIntegrityProof {
  const config: ProofConfig = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    proofPurpose: opts.proofPurpose ?? 'assertionMethod',
    verificationMethod: opts.verificationMethod,
    // Conditionally spread rather than always assigning `created: opts.created`
    // — an explicit `created: undefined` key would still show up in
    // Object.keys() and get JCS-canonicalized as null-ish, corrupting the
    // signed bytes relative to a proof that genuinely omits `created`.
    ...(opts.created ? { created: opts.created } : {}),
  }
  const signingInput = hashConfigAndDoc(config, document)
  const signature = ed25519.sign(signingInput, opts.privateKey)
  return { ...config, proofValue: 'z' + base58.encode(signature) }
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
