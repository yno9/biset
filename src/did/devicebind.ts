// Per-device JMAP credential (account-model redesign, see ARC.md's identity
// layer notes). Each device that wants to use a JMAP relay holds its OWN
// ed25519 keypair, generated locally and never derived from the shared seed
// — same reasoning as didcomm-devices.ts's generateDeviceDidCommKey: a
// seed-derived key would be identical across every device restoring the same
// 24 words, which is exactly what made per-device DIDComm delivery collide
// before that file switched to local random generation (see its own note).
// A shared key here would make the same mistake for JMAP login: no way to
// revoke one device without invalidating every device at once.
//
// The identity's ROOT key vouches for a device key once — "this DID
// authorizes this device to act as itself" — the anchor verifies that
// against the DID's CURRENT root key (verifyDeviceVouch in
// src/anchor/didbind.ts, via the same rootKeyResolver provisioning already
// uses), so a prior key rotation never invalidates a still-held vouch: the
// resolver always follows the DID to whatever key currently controls it.
// After the vouch, ongoing logins are signed by the DEVICE key alone; the
// root key and the 24-word phrase are never touched again for routine use —
// only to vouch for a NEW device, or to recover when every device is lost.
//
// Vouch statement (root-key-signed, freshness-windowed like binding.ts's
// bind: statement — the window guards the ACT of vouching against replay,
// not the resulting authorization's lifetime, which lasts until explicit
// revocation):
//   devkey:<did>:<devicePubKeyB64url>:<label>:<unixSeconds>
//
// Session-login statement (device-key-signed; the relay checks it against
// the device pubkey it already has on file — no DID resolution, so this step
// never touches DID material at all). Host-bound like binding.ts's bind:
// statement (2026-08-16 — the session statement was the one signed statement
// in this file that had DROPPED the host, unlike vouch: above): without it, a
// device signature captured by one relay (over TLS or not — a relay itself
// can misbehave, or a network intermediary the client trusts less than the
// relay) verifies just as well replayed against a DIFFERENT relay this
// device is also registered with, within the freshness window. `ts` alone
// stops an EXPIRED signature from being replayed; it does no work at all
// against a replay to a different host inside the same window — that is what
// `relayHost` closes. Still not a server-issued nonce (each relay reports the
// host IT observed, the same "first-hand, off the transport" shape
// anchor/didbind.ts's bind: check uses, not a value this relay generates and
// remembers) — a genuine nonce would also stop a same-relay, same-window
// replay, which this does not, and needs a challenge round trip this
// lightweight a credential does not otherwise require. Tracked as a real gap,
// not assumed closed:
//   session:<did>:<devicePubKeyB64url>:<relayHost>:<unixSeconds>
import { ed25519 } from '@noble/curves/ed25519.js'

const enc = new TextEncoder()

export interface DeviceKeyPair { publicKey: Uint8Array; privateKey: Uint8Array }

// Generated locally, per device — never derived from the master seed
// (didcomm-devices.ts's generateDeviceDidCommKey precedent, same reasoning).
export function generateDeviceKey(): DeviceKeyPair {
  const privateKey = crypto.getRandomValues(new Uint8Array(32))
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) }
}

// Local, not imported from utils.ts: this file is shared into the anchor's
// DOM-free build the same way dht/document.ts's own b64url helpers are (see
// that file's note) — utils.ts is a DOM-touching grab-bag that would break it.
export function b64urlEncode(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
export function b64urlDecode(s: string): Uint8Array {
  const pad = (4 - (s.length % 4)) % 4
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function b64(bytes: Uint8Array): string {
  let s = ''; for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}
function b64decode(s: string): Uint8Array {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function vouchStatement(did: string, devicePubKeyB64url: string, label: string, ts: number): string {
  return `devkey:${did}:${devicePubKeyB64url}:${label}:${ts}`
}

export interface VouchProof { did: string; devicePubKey: string /* b64url */; label: string; ts: number; sig: string /* base64 */ }

// Signed by the identity's ROOT key: "this DID authorizes this device pubkey
// for JMAP login." One-time, at device setup — never repeated for routine use.
export function signVouch(
  rootPrivateKey: Uint8Array, did: string, devicePublicKey: Uint8Array, label: string,
  ts: number = Math.floor(Date.now() / 1000),
): VouchProof {
  const devicePubKey = b64urlEncode(devicePublicKey)
  const sig = ed25519.sign(enc.encode(vouchStatement(did, devicePubKey, label, ts)), rootPrivateKey)
  return { did, devicePubKey, label, ts, sig: b64(sig) }
}

export function sessionLoginStatement(did: string, devicePubKeyB64url: string, relayHost: string, nonce: string, ts: number): string {
  return `session:${did}:${devicePubKeyB64url}:${relayHost}:${nonce}:${ts}`
}

export interface SessionLoginProof { did: string; devicePubKey: string /* b64url */; relayHost: string; nonce: string; ts: number; sig: string /* base64 */ }

// Signed by the DEVICE's own key: "I am the device this vouch authorized,
// let me in." Used for every ordinary login — root key and mnemonic are
// never involved here, so this step is completely unaffected by any later
// root-key rotation (unlike the vouch step, this one doesn't even need to
// resolve the DID document at all).
//
// `nonce` comes from the relay's own `GET /account/session/challenge`
// (SPEC.md §11.28 on the relay side) — single-use, so a captured-and-
// replayed POST of this exact statement fails even inside the freshness
// window `ts` alone would still be within. `relayHost` alone only stopped a
// replay against a DIFFERENT relay; the nonce is what closes the same-relay
// case.
export function signSessionLogin(
  devicePrivateKey: Uint8Array, did: string, relayHost: string, nonce: string,
  ts: number = Math.floor(Date.now() / 1000),
): SessionLoginProof {
  const devicePubKey = b64urlEncode(ed25519.getPublicKey(devicePrivateKey))
  const sig = ed25519.sign(enc.encode(sessionLoginStatement(did, devicePubKey, relayHost, nonce, ts)), devicePrivateKey)
  return { did, devicePubKey, relayHost, nonce, ts, sig: b64(sig) }
}

// Client-side sanity check (the relay does the authoritative one, against
// its own on-file device pubkey — see this file's header). Verifies the
// proof's signature against the device pubkey it itself names. Does NOT (and
// cannot) check that `nonce` was genuinely issued or is still unspent — only
// the relay's own nonce store knows that.
export function verifySessionLoginProof(proof: SessionLoginProof): boolean {
  try {
    const sig = b64decode(proof.sig)
    const msg = enc.encode(sessionLoginStatement(proof.did, proof.devicePubKey, proof.relayHost, proof.nonce, proof.ts))
    return ed25519.verify(sig, msg, b64urlDecode(proof.devicePubKey))
  } catch { return false }
}
