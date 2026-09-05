/** Client-side Minimal Metadata Room identity-link encryption (PLAN §7.2). */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlToBytes, bytesToBase64url, canonicalBytes } from '../../../shared/protocol/canonical.ts'
import type { MimiRoomId, PseudonymousCredential } from '../../../shared/mimi/protocol-types.ts'

const IDENTITY_LINK_EXPORTER_LABEL = 'mimi mmr identity-link'
const KEY_BYTES = 32
const NONCE_BYTES = 24

/** The MLS client owns this capability; the hub must never implement it. */
export interface MmrEpochExporter {
  exportSecret(label: string, context: Uint8Array, length: number): Promise<Uint8Array>
}

/** draft §6.1's encrypted IdentityLinkTBE.  It is never provider-visible. */
export interface IdentityLinkTbe {
  pseudonymousCredentialSignature: Uint8Array
  clientCredential: Uint8Array
}

export type PseudonymousCredentialTbs = Pick<PseudonymousCredential, 'clientPseudonym' | 'userPseudonym' | 'signaturePublicKey'>
export type PseudonymousCredentialSigner = (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>
/** MLS-layer validation of the decrypted real credential and its signing key. */
export type IdentityLinkClientCredentialVerifier = (clientCredential: Uint8Array, signaturePublicKey: Uint8Array) => boolean | Promise<boolean>

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

/** Encrypts the draft-defined real-credential link and binds it to the pseudonym. */
export async function encryptIdentityLinkTbe(
  exporter: MmrEpochExporter,
  roomId: MimiRoomId,
  credential: PseudonymousCredentialTbs,
  clientCredential: Uint8Array,
  sign: PseudonymousCredentialSigner,
): Promise<Uint8Array> {
  if (clientCredential.length === 0) throw new TypeError('identity link requires a client credential')
  const signature = await sign(pseudonymousCredentialTbsBytes(credential))
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new TypeError('pseudonymous credential signature is invalid')
  return encryptIdentityLink(exporter, roomId, encodeIdentityLinkTbe({ pseudonymousCredentialSignature: signature, clientCredential }))
}

/** Decrypts and verifies the identity link before exposing its real credential. */
export async function decryptAndVerifyIdentityLink(
  exporter: MmrEpochExporter,
  roomId: MimiRoomId,
  credential: PseudonymousCredential,
  verifyClientCredential: IdentityLinkClientCredentialVerifier,
): Promise<IdentityLinkTbe> {
  const link = decodeIdentityLinkTbe(await decryptIdentityLink(exporter, roomId, credential.identityLinkCiphertext))
  if (!ed25519.verify(link.pseudonymousCredentialSignature, pseudonymousCredentialTbsBytes(credential), credential.signaturePublicKey)) {
    throw new TypeError('identity link does not bind to its pseudonymous credential')
  }
  if (!(await verifyClientCredential(link.clientCredential, credential.signaturePublicKey))) throw new TypeError('identity link real credential does not match its signing key')
  return link
}

function pseudonymousCredentialTbsBytes(credential: PseudonymousCredentialTbs): Uint8Array {
  if (!credential.clientPseudonym || !credential.userPseudonym || credential.signaturePublicKey.length !== 32) throw new TypeError('pseudonymous credential TBS is invalid')
  return canonicalBytes({ label: 'PseudonymousCredentialTBS', clientPseudonym: credential.clientPseudonym, userPseudonym: credential.userPseudonym, signaturePublicKey: bytesToBase64url(credential.signaturePublicKey) })
}

async function identityLinkKey(exporter: MmrEpochExporter, roomId: MimiRoomId): Promise<Uint8Array> {
  const key = await exporter.exportSecret(IDENTITY_LINK_EXPORTER_LABEL, identityLinkContext(roomId), KEY_BYTES)
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) throw new TypeError('MLS exporter returned an invalid identity-link key')
  return key.slice()
}

function identityLinkContext(roomId: MimiRoomId): Uint8Array {
  if (!roomId) throw new TypeError('room ID is required')
  return canonicalBytes({ label: IDENTITY_LINK_EXPORTER_LABEL, roomId })
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const out = new Uint8Array(left.length + right.length)
  out.set(left); out.set(right, left.length)
  return out
}

function encodeIdentityLinkTbe(value: IdentityLinkTbe): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ pseudonymousCredentialSignature: bytesToBase64url(value.pseudonymousCredentialSignature), clientCredential: bytesToBase64url(value.clientCredential) }))
}

function decodeIdentityLinkTbe(bytes: Uint8Array): IdentityLinkTbe {
  let value: unknown
  try { value = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('identity link is not valid JSON') }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('identity link must be an object')
  const input = value as Record<string, unknown>
  if (typeof input.pseudonymousCredentialSignature !== 'string' || typeof input.clientCredential !== 'string') throw new TypeError('identity link is malformed')
  let signature: Uint8Array
  let clientCredential: Uint8Array
  try { signature = base64urlToBytes(input.pseudonymousCredentialSignature); clientCredential = base64urlToBytes(input.clientCredential) } catch { throw new TypeError('identity link binary fields are invalid') }
  if (signature.length !== 64 || clientCredential.length === 0) throw new TypeError('identity link binary fields are invalid')
  return { pseudonymousCredentialSignature: signature, clientCredential }
}
