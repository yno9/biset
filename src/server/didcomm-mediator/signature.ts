// DIDComm signed messages (signature.md), EdDSA/Ed25519 only. Used for the
// one case where the mediator must answer a sender it cannot authenticate
// (an anoncrypt Forward it refuses to queue): signed rather than encrypted,
// so the refusal is provable (this mediator said it) without needing a
// recipient to encrypt to. Ported from src.bak/did/didcomm/signature.ts,
// trimmed to pack-only (the mediator never receives a signed message).
import { ed25519 } from '@noble/curves/ed25519.js'
import { b64url } from '../../shared/didcomm/crypto.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)

export interface SignedJWS {
  payload: string
  protected: string
  signature: string
}

export interface JwsSigner {
  /** A DID URL from the signer's `authentication` section. */
  kid: string
  edPrivateKey: Uint8Array
}

/** Signs plaintext JWM bytes, producing a flattened JWS. */
export function packSigned(plaintext: Uint8Array, signer: JwsSigner): SignedJWS {
  const protectedHeader = { typ: 'application/didcomm-signed+json', alg: 'EdDSA', kid: signer.kid }
  const protectedB64 = b64url(utf8(JSON.stringify(protectedHeader)))
  const payloadB64 = b64url(plaintext)
  const signingInput = utf8(`${protectedB64}.${payloadB64}`)
  const signature = ed25519.sign(signingInput, signer.edPrivateKey)
  return { payload: payloadB64, protected: protectedB64, signature: b64url(signature) }
}
