// Signed BEP44 / Pkarr-relay payload assembly and parsing — the bytes that go
// over the gateway HTTP body and into the DHT.
//
// Payload wire format (Pkarr relay, design/relays.md):
//   signature(64) ‖ seq(8, big-endian) ‖ dns-packet(raw, <1000B)
// The signature is ed25519 over the BEP44 canonical buffer for an empty salt:
//   "3:seqi<seq>e1:v" ‖ "<len>:" ‖ dns-packet
// (proven byte-identical to anacrolix/dht's bep44 signing — see the Go PoC).
//
// seq unit: the did:dht spec mandates the Unix timestamp in SECONDS (Pkarr's own
// tooling uses microseconds — the byte layout is identical, only the magnitude
// differs; biset follows did:dht since its identifiers are did:dht DIDs).
import { ed25519 } from '@noble/curves/ed25519.js'
import { encodePacket, decodePacket } from './dns.ts'
import { documentToRecords, recordsToDocument, type DidDocument } from './document.ts'
import { didFromRootPublicKey } from './keys.ts'

const enc = new TextEncoder()

function canonicalBufferToSign(seq: number, dnsPacket: Uint8Array): Uint8Array {
  const prefix = enc.encode(`3:seqi${seq}e1:v${dnsPacket.length}:`)
  const out = new Uint8Array(prefix.length + dnsPacket.length)
  out.set(prefix, 0)
  out.set(dnsPacket, prefix.length)
  return out
}

function seqTo8BE(seq: number): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(seq), false)
  return b
}
function seqFrom8BE(b: Uint8Array): number {
  return Number(new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, false))
}

export function nowSeq(): number {
  return Math.floor(Date.now() / 1000)
}

// DID document → signed payload bytes ready for a gateway PUT.
export function buildSignedPayload(rootPrivateKey: Uint8Array, doc: DidDocument, seq: number = nowSeq()): Uint8Array {
  const dnsPacket = encodePacket(documentToRecords(doc))
  if (dnsPacket.length >= 1000) throw new Error(`DNS packet ${dnsPacket.length}B exceeds BEP44 1000B limit`)
  const sig = ed25519.sign(canonicalBufferToSign(seq, dnsPacket), rootPrivateKey)
  const out = new Uint8Array(64 + 8 + dnsPacket.length)
  out.set(sig, 0)
  out.set(seqTo8BE(seq), 64)
  out.set(dnsPacket, 72)
  return out
}

export interface ParsedPayload { seq: number; document: DidDocument }

// Signed payload bytes (from a gateway GET) → verified DID document. The public
// key is the identity key recovered from the DID's own z-base-32 suffix, so a
// gateway cannot substitute a different key: the signature must verify against
// the very key the DID names.
export function parseSignedPayload(identityPublicKey: Uint8Array, payload: Uint8Array): ParsedPayload {
  if (payload.length < 72) throw new Error('payload too short')
  const sig = payload.subarray(0, 64)
  const seq = seqFrom8BE(payload.subarray(64, 72))
  const dnsPacket = payload.subarray(72)
  if (!ed25519.verify(sig, canonicalBufferToSign(seq, dnsPacket), identityPublicKey)) {
    throw new Error('DID payload signature verification failed')
  }
  const did = didFromRootPublicKey(identityPublicKey)
  return { seq, document: recordsToDocument(did, decodePacket(dnsPacket)) }
}
