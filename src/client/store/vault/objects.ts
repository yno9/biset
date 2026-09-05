import { bytesToBase64url, canonicalHash, equalBytes } from '../../../shared/protocol/canonical.ts'
import type { SegmentId, VaultObjectId } from '../../../shared/protocol/ids.ts'
import type { VaultObjectV1 } from '../../../shared/protocol/vault.ts'

const AES_GCM_KEY_BYTES = 32
const AES_GCM_NONCE_BYTES = 12

export interface VaultObjectDraft {
  segmentId: SegmentId
  plaintext: Uint8Array
  aad: Uint8Array
}

export function createSegmentKey(): Uint8Array {
  const key = new Uint8Array(AES_GCM_KEY_BYTES)
  crypto.getRandomValues(key)
  return key
}

export async function encryptVaultObject(segmentKey: Uint8Array, draft: VaultObjectDraft): Promise<VaultObjectV1> {
  assertKey(segmentKey)
  if (!draft.segmentId) throw new TypeError('segmentId is required')
  const nonce = new Uint8Array(AES_GCM_NONCE_BYTES)
  crypto.getRandomValues(nonce)
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: arrayBuffer(nonce), additionalData: arrayBuffer(draft.aad) },
    await importAesKey(segmentKey, ['encrypt']),
    arrayBuffer(draft.plaintext),
  ))
  const object: VaultObjectV1 = {
    version: 1,
    objectId: '',
    segmentId: draft.segmentId,
    nonce,
    ciphertext,
    ciphertextHash: new Uint8Array(),
    plaintextLength: draft.plaintext.length,
    aad: draft.aad.slice(),
  }
  object.ciphertextHash = await digest(ciphertext)
  object.objectId = objectId(object)
  return object
}

export async function decryptVaultObject(segmentKey: Uint8Array, object: VaultObjectV1): Promise<Uint8Array> {
  assertKey(segmentKey)
  if (object.version !== 1 || object.objectId !== objectId(object)) throw new TypeError('vault object ID does not match ciphertext metadata')
  if (!equalBytes(object.ciphertextHash, await digest(object.ciphertext))) throw new TypeError('vault object ciphertext hash does not match')
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: arrayBuffer(object.nonce), additionalData: arrayBuffer(object.aad) },
      await importAesKey(segmentKey, ['decrypt']),
      arrayBuffer(object.ciphertext),
    ))
  } catch {
    throw new TypeError('vault object decryption failed')
  }
}

/** Checks content addressing and ciphertext integrity without needing a key. */
export async function verifyVaultObjectIntegrity(object: VaultObjectV1): Promise<boolean> {
  return object.version === 1
    && object.objectId === objectId(object)
    && equalBytes(object.ciphertextHash, await digest(object.ciphertext))
}

function vaultObjectId(object: Omit<VaultObjectV1, 'objectId'> | VaultObjectV1): VaultObjectId {
  return objectId(object)
}

function objectId(object: Omit<VaultObjectV1, 'objectId'> | VaultObjectV1): VaultObjectId {
  return canonicalHash('biset/vault/object-id/v1', {
    version: object.version,
    segmentId: object.segmentId,
    nonce: bytesToBase64url(object.nonce),
    ciphertext: bytesToBase64url(object.ciphertext),
    ciphertextHash: bytesToBase64url(object.ciphertextHash),
    plaintextLength: object.plaintextLength,
    aad: bytesToBase64url(object.aad),
  })
}

async function digest(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBuffer(bytes)))
}

async function importAesKey(key: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', arrayBuffer(key), 'AES-GCM', false, usages)
}

function assertKey(key: Uint8Array): void {
  if (key.length !== AES_GCM_KEY_BYTES) throw new TypeError('SegmentKey must be 32 bytes')
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)
  return copy.buffer
}
