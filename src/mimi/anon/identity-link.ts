/** Client-side Minimal Metadata Room identity-link encryption (PLAN §7.2). */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { canonicalBytes } from '../../protocol/canonical.ts'
import type { MimiRoomId } from '../protocol-types.ts'

export const IDENTITY_LINK_EXPORTER_LABEL = 'mimi mmr identity-link'
const KEY_BYTES = 32
const NONCE_BYTES = 24

/** The MLS client owns this capability; the hub must never implement it. */
export interface MmrEpochExporter {
  exportSecret(label: string, context: Uint8Array, length: number): Promise<Uint8Array>
}

export async function encryptIdentityLink(exporter: MmrEpochExporter, roomId: MimiRoomId, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await identityLinkKey(exporter, roomId)
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  return concat(nonce, xchacha20poly1305(key, nonce, identityLinkContext(roomId)).encrypt(plaintext))
}

export async function decryptIdentityLink(exporter: MmrEpochExporter, roomId: MimiRoomId, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length <= NONCE_BYTES) throw new TypeError('identity link ciphertext is truncated')
  const key = await identityLinkKey(exporter, roomId)
  return xchacha20poly1305(key, ciphertext.slice(0, NONCE_BYTES), identityLinkContext(roomId)).decrypt(ciphertext.slice(NONCE_BYTES))
}

export async function identityLinkKey(exporter: MmrEpochExporter, roomId: MimiRoomId): Promise<Uint8Array> {
  const key = await exporter.exportSecret(IDENTITY_LINK_EXPORTER_LABEL, identityLinkContext(roomId), KEY_BYTES)
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) throw new TypeError('MLS exporter returned an invalid identity-link key')
  return key.slice()
}

export function identityLinkContext(roomId: MimiRoomId): Uint8Array {
  if (!roomId) throw new TypeError('room ID is required')
  return canonicalBytes({ label: IDENTITY_LINK_EXPORTER_LABEL, roomId })
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const out = new Uint8Array(left.length + right.length)
  out.set(left); out.set(right, left.length)
  return out
}
