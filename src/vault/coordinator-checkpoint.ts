import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../protocol/canonical.ts'
import type { DeliverySeq, VaultId } from '../protocol/ids.ts'
import { decodeRecoveryArchiveSnapshot, encodeRecoveryArchiveSnapshot, type RecoveryArchiveSnapshotV1 } from './recovery-archive.ts'

const KEY_BYTES = 32
const NONCE_BYTES = 12

interface CoordinatorCheckpointEnvelopeV1 {
  version: 1 | 2
  wrapNonce: Uint8Array
  wrappedDataKey: Uint8Array
  dataNonce: Uint8Array
  ciphertext: Uint8Array
  ciphertextHash: Uint8Array
  plaintextLength: number
}

export function deriveVaultRecoveryKek(masterSeed: Uint8Array, vaultId: VaultId): Uint8Array {
  if (masterSeed.length < 32) throw new TypeError('Vault recovery master seed is invalid')
  const salt = sha256(canonicalBytes({ label: 'biset/vault-recovery-kek/salt/v2', vaultId }))
  return hkdf(sha256, masterSeed, salt, canonicalBytes({ label: 'biset/vault-recovery-kek/info/v2' }), KEY_BYTES)
}

/** v2 is portable between Coordinator operators: server origin is routing,
 * not part of durable storage identity. */
export async function createPortableCoordinatorCheckpoint(masterSeed: Uint8Array, snapshot: RecoveryArchiveSnapshotV1, context: { vaultId: VaultId; coveredSeq: DeliverySeq }): Promise<Uint8Array> {
  const kek = deriveVaultRecoveryKek(masterSeed, context.vaultId)
  const aad = canonicalBytes({ label: 'biset/vault-checkpoint/aad/v2', vaultId: context.vaultId, coveredSeq: context.coveredSeq })
  const dataKey = crypto.getRandomValues(new Uint8Array(KEY_BYTES))
  const wrapNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const dataNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  try {
    const wrappedDataKey = await aesEncrypt(kek, wrapNonce, aad, dataKey)
    const plaintext = encodeRecoveryArchiveSnapshot(snapshot)
    const ciphertext = await aesEncrypt(dataKey, dataNonce, aad, plaintext)
    return encodeEnvelope({ version: 2, wrapNonce, wrappedDataKey, dataNonce, ciphertext, ciphertextHash: sha256(ciphertext), plaintextLength: plaintext.length })
  } finally { kek.fill(0); dataKey.fill(0) }
}

export async function openPortableCoordinatorCheckpoint(masterSeed: Uint8Array, payload: Uint8Array, context: { vaultId: VaultId; coveredSeq: DeliverySeq; coordinatorUrl: string }): Promise<RecoveryArchiveSnapshotV1> {
  const envelope = decodeEnvelope(payload)
  const kek = envelope.version === 2 ? deriveVaultRecoveryKek(masterSeed, context.vaultId) : deriveCoordinatorRecoveryKek(masterSeed, context.vaultId, context.coordinatorUrl)
  const aad = envelope.version === 2 ? canonicalBytes({ label: 'biset/vault-checkpoint/aad/v2', vaultId: context.vaultId, coveredSeq: context.coveredSeq }) : checkpointAad(context)
  try {
    if (!equalBytes(envelope.ciphertextHash, sha256(envelope.ciphertext))) throw new TypeError('Coordinator checkpoint ciphertext hash does not match')
    const dataKey = await aesDecrypt(kek, envelope.wrapNonce, aad, envelope.wrappedDataKey).catch(() => { throw new TypeError('Coordinator checkpoint key cannot be unwrapped') })
    try {
      const plaintext = await aesDecrypt(dataKey, envelope.dataNonce, aad, envelope.ciphertext).catch(() => { throw new TypeError('Coordinator checkpoint cannot be decrypted') })
      if (plaintext.length !== envelope.plaintextLength) throw new TypeError('Coordinator checkpoint plaintext length does not match')
      return decodeRecoveryArchiveSnapshot(plaintext)
    } finally { dataKey.fill(0) }
  } finally { kek.fill(0) }
}

/** Domain-separated recovery KEK. The Coordinator origin prevents the same
 * recovery phrase from producing a correlatable key at another operator. */
export function deriveCoordinatorRecoveryKek(masterSeed: Uint8Array, vaultId: VaultId, coordinatorUrl: string): Uint8Array {
  if (masterSeed.length < 32) throw new TypeError('Coordinator recovery master seed is invalid')
  const origin = coordinatorOrigin(coordinatorUrl)
  const salt = sha256(canonicalBytes({ label: 'biset/coordinator/recovery-kek/salt/v1', vaultId, coordinatorOrigin: origin }))
  return hkdf(sha256, masterSeed, salt, canonicalBytes({ label: 'biset/coordinator/recovery-kek/info/v1' }), KEY_BYTES)
}

/** Encrypts a complete Vault snapshot with a fresh random data key, itself
 * wrapped by the root-phrase-derived KEK. No identity metadata is exposed in
 * the serialized envelope. */
export async function createCoordinatorCheckpoint(
  recoveryKek: Uint8Array,
  snapshot: RecoveryArchiveSnapshotV1,
  context: { vaultId: VaultId; coveredSeq: DeliverySeq; coordinatorUrl: string },
): Promise<Uint8Array> {
  assertKey(recoveryKek)
  const aad = checkpointAad(context)
  const dataKey = crypto.getRandomValues(new Uint8Array(KEY_BYTES))
  const wrapNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const dataNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  try {
    const wrappedDataKey = await aesEncrypt(recoveryKek, wrapNonce, aad, dataKey)
    const plaintext = encodeRecoveryArchiveSnapshot(snapshot)
    const ciphertext = await aesEncrypt(dataKey, dataNonce, aad, plaintext)
    return encodeEnvelope({ version: 1, wrapNonce, wrappedDataKey, dataNonce, ciphertext, ciphertextHash: sha256(ciphertext), plaintextLength: plaintext.length })
  } finally {
    dataKey.fill(0)
  }
}

export async function openCoordinatorCheckpoint(
  recoveryKek: Uint8Array,
  payload: Uint8Array,
  context: { vaultId: VaultId; coveredSeq: DeliverySeq; coordinatorUrl: string },
): Promise<RecoveryArchiveSnapshotV1> {
  assertKey(recoveryKek)
  const envelope = decodeEnvelope(payload)
  if (!equalBytes(envelope.ciphertextHash, sha256(envelope.ciphertext))) throw new TypeError('Coordinator checkpoint ciphertext hash does not match')
  const aad = checkpointAad(context)
  let dataKey: Uint8Array
  try { dataKey = await aesDecrypt(recoveryKek, envelope.wrapNonce, aad, envelope.wrappedDataKey) }
  catch { throw new TypeError('Coordinator checkpoint key cannot be unwrapped') }
  try {
    if (dataKey.length !== KEY_BYTES) throw new TypeError('Coordinator checkpoint data key is invalid')
    let plaintext: Uint8Array
    try { plaintext = await aesDecrypt(dataKey, envelope.dataNonce, aad, envelope.ciphertext) }
    catch { throw new TypeError('Coordinator checkpoint cannot be decrypted') }
    if (plaintext.length !== envelope.plaintextLength) throw new TypeError('Coordinator checkpoint plaintext length does not match')
    return decodeRecoveryArchiveSnapshot(plaintext)
  } finally {
    dataKey.fill(0)
  }
}

function checkpointAad(context: { vaultId: VaultId; coveredSeq: DeliverySeq; coordinatorUrl: string }): Uint8Array {
  return canonicalBytes({ label: 'biset/coordinator/checkpoint/aad/v1', vaultId: context.vaultId, coveredSeq: context.coveredSeq, coordinatorOrigin: coordinatorOrigin(context.coordinatorUrl) })
}

function encodeEnvelope(value: CoordinatorCheckpointEnvelopeV1): Uint8Array {
  assertEnvelope(value)
  return canonicalBytes({ version: value.version, wrapNonce: bytesToBase64url(value.wrapNonce), wrappedDataKey: bytesToBase64url(value.wrappedDataKey), dataNonce: bytesToBase64url(value.dataNonce), ciphertext: bytesToBase64url(value.ciphertext), ciphertextHash: bytesToBase64url(value.ciphertextHash), plaintextLength: value.plaintextLength })
}

function decodeEnvelope(bytes: Uint8Array): CoordinatorCheckpointEnvelopeV1 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { throw new TypeError('Coordinator checkpoint is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Coordinator checkpoint must be an object')
  const value = input as Record<string, unknown>
  if (Object.keys(value).sort().join() !== ['ciphertext', 'ciphertextHash', 'dataNonce', 'plaintextLength', 'version', 'wrapNonce', 'wrappedDataKey'].sort().join() || (value.version !== 1 && value.version !== 2) || typeof value.wrapNonce !== 'string' || typeof value.wrappedDataKey !== 'string' || typeof value.dataNonce !== 'string' || typeof value.ciphertext !== 'string' || typeof value.ciphertextHash !== 'string' || typeof value.plaintextLength !== 'number') throw new TypeError('Coordinator checkpoint shape is invalid')
  const envelope: CoordinatorCheckpointEnvelopeV1 = { version: value.version, wrapNonce: base64urlToBytes(value.wrapNonce), wrappedDataKey: base64urlToBytes(value.wrappedDataKey), dataNonce: base64urlToBytes(value.dataNonce), ciphertext: base64urlToBytes(value.ciphertext), ciphertextHash: base64urlToBytes(value.ciphertextHash), plaintextLength: value.plaintextLength }
  assertEnvelope(envelope)
  if (!equalBytes(bytes, encodeEnvelope(envelope))) throw new TypeError('Coordinator checkpoint is not canonical')
  return envelope
}

function assertEnvelope(value: CoordinatorCheckpointEnvelopeV1): void {
  if ((value.version !== 1 && value.version !== 2) || value.wrapNonce.length !== NONCE_BYTES || value.wrappedDataKey.length !== KEY_BYTES + 16 || value.dataNonce.length !== NONCE_BYTES || value.ciphertext.length === 0 || value.ciphertextHash.length !== 32 || !Number.isSafeInteger(value.plaintextLength) || value.plaintextLength < 0) throw new TypeError('Coordinator checkpoint envelope is invalid')
}

async function aesEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: buffer(nonce), additionalData: buffer(aad) }, await crypto.subtle.importKey('raw', buffer(key), 'AES-GCM', false, ['encrypt']), buffer(plaintext)))
}
async function aesDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buffer(nonce), additionalData: buffer(aad) }, await crypto.subtle.importKey('raw', buffer(key), 'AES-GCM', false, ['decrypt']), buffer(ciphertext)))
}
function buffer(value: Uint8Array): ArrayBuffer { return Uint8Array.from(value).buffer }
function assertKey(value: Uint8Array): void { if (value.length !== KEY_BYTES) throw new TypeError('Coordinator recovery KEK must contain 32 bytes') }
function coordinatorOrigin(value: string): string { const url = new URL(value); if (url.protocol !== 'https:' || url.username || url.password) throw new TypeError('Coordinator URL must be HTTPS'); return url.origin }
