// Persists the mediator's own did:peer keypair across restarts. Unlike the
// in-memory message queue (fine to lose on restart — senders re-send), the
// mediator's own DID must stay stable: every client's mediate-request and
// keylist-update targets this DID's keyAgreement kid, so a new DID on every
// restart would silently orphan every existing registration.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlDecodeToBytes, identityFromKeys, type PeerIdentity } from '../../did/peer.ts'

interface StoredIdentity {
  xPriv: string // b64url
  edPriv: string // b64url
}

function loadOrCreateKeypair(file: string): { xPriv: Uint8Array; edPriv: Uint8Array } {
  if (existsSync(file)) {
    const stored: StoredIdentity = JSON.parse(readFileSync(file, 'utf-8'))
    return { xPriv: b64urlDecodeToBytes(stored.xPriv), edPriv: b64urlDecodeToBytes(stored.edPriv) }
  }
  const xPriv = x25519.utils.randomSecretKey()
  const edPriv = ed25519.utils.randomSecretKey()
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  const stored: StoredIdentity = { xPriv: b64url(xPriv), edPriv: b64url(edPriv) }
  writeFileSync(file, JSON.stringify(stored, null, 2), { mode: 0o600 })
  return { xPriv, edPriv }
}

/** The mediator's stable identity, its service segment pointing at its own
 * public URL — that URL is how a client's DID document tells correspondents
 * where to deliver, so it is part of the DID rather than a runtime detail. */
export function loadMediatorIdentity(file: string, publicUrl: string): PeerIdentity {
  const { xPriv, edPriv } = loadOrCreateKeypair(file)
  return identityFromKeys(xPriv, edPriv, { uri: publicUrl, accept: ['didcomm/v2'] })
}
