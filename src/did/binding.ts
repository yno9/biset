// Signature-based DID→relay binding (DID.md third-party portability). To bind an
// identity to a relay WITHOUT handing over any secret, the client signs a binding
// statement with the DID's ROOT key; the relay verifies it against the DID's own
// public key (the z-base-32 suffix), so control of the DID is proven by signature
// alone — never by revealing the seed, envelope, or a replayable token.
//
// Statement (host-bound to stop cross-relay replay of a captured signature):
//   bind:<did>:<username>@<relayHost>:<unixSeconds>
import { ed25519 } from '@noble/curves/ed25519.js'

const enc = new TextEncoder()

export function bindingStatement(did: string, username: string, relayHost: string, ts: number): string {
  return `bind:${did}:${username}@${relayHost}:${ts}`
}

export interface BindingProof { did: string; username: string; ts: number; sig: string /* base64 */ }

export function signBinding(rootPrivateKey: Uint8Array, did: string, username: string, relayHost: string, ts: number = Math.floor(Date.now() / 1000)): BindingProof {
  const msg = enc.encode(bindingStatement(did, username, relayHost, ts))
  const sig = ed25519.sign(msg, rootPrivateKey)
  let s = ''; for (const b of sig) s += String.fromCharCode(b)
  return { did, username, ts, sig: btoa(s) }
}
