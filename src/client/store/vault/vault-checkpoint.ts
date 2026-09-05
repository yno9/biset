import { sha256 } from '@noble/hashes/sha2.js'
import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../../../shared/protocol/canonical.ts'
import { assertMlsEpoch, type DeliverySeq, type MlsEpoch, type VaultId } from '../../../shared/protocol/ids.ts'
import { decodeRecoveryArchiveSnapshot, encodeRecoveryArchiveSnapshot, type RecoveryArchiveSnapshotV1 } from './recovery-archive.ts'

const KEY_BYTES = 32
const NONCE_BYTES = 12
const ENVELOPE_KEYS = ['ciphertext', 'ciphertextHash', 'dataNonce', 'epoch', 'plaintextLength', 'selfGroupId', 'version', 'wrapNonce', 'wrappedDataKey'].sort().join()

/** Which self-group epoch's VEK wraps a checkpoint's `dataKey`. */
export interface VaultCheckpointEpoch {
  selfGroupId: string
  epoch: MlsEpoch
}

/** Storage identity of the checkpoint, bound into the AAD of both layers. */
export interface VaultCheckpointContext {
  vaultId: VaultId
  coveredSeq: DeliverySeq
}

/**
 * v3 checkpoint envelope. Two layers, unchanged since v2: a random `dataKey`
 * encrypts the snapshot, and a KEK wraps that `dataKey`. Only the KEK moved --
 * v1 (retired Coordinator origin) and v2 (`masterSeed`) both derived it from a
 * secret this client no longer has, so v3 wraps under the Vault Epoch Key of
 * the MIMI Self Vault's own MLS self group, the same key `vault/crypto.ts`
 * already wraps SegmentKeys under. `selfGroupId`/`epoch` say which VEK opens
 * it; they are cleartext because a device must be able to decide whether it
 * can derive that VEK at all before trying, and they are covered by the AAD
 * so neither can be swapped for another epoch's.
 */
interface VaultCheckpointEnvelopeV3 extends VaultCheckpointEpoch {
  version: 3
  wrapNonce: Uint8Array
  wrappedDataKey: Uint8Array
  dataNonce: Uint8Array
  ciphertext: Uint8Array
  ciphertextHash: Uint8Array
  plaintextLength: number
}

/**
 * The checkpoint is intact but its VEK is gone: `MlsVaultEpochKeyResolver`
 * only ever derives the CURRENT epoch's key, so an epoch that has already
 * advanced can never be re-derived (that is MLS forward secrecy, not a bug).
 * Distinct from an ordinary restore failure because the recovery is different:
 * nothing about this checkpoint can be repaired, a device holding the full
 * Vault has to publish a fresh one at the current epoch instead.
 */
export class VaultCheckpointEpochUnavailableError extends Error {
  constructor(readonly checkpointEpoch: VaultCheckpointEpoch, readonly currentEpoch: VaultCheckpointEpoch) {
    super(`Vault checkpoint was sealed for ${checkpointEpoch.selfGroupId}@${checkpointEpoch.epoch}, but this device is at ${currentEpoch.selfGroupId}@${currentEpoch.epoch}`)
    this.name = 'VaultCheckpointEpochUnavailableError'
  }
}

export function sameVaultCheckpointEpoch(left: VaultCheckpointEpoch, right: VaultCheckpointEpoch): boolean {
  return left.selfGroupId === right.selfGroupId && left.epoch === right.epoch
}

export async function createVaultCheckpoint(
  vaultEpochKey: Uint8Array,
  snapshot: RecoveryArchiveSnapshotV1,
  context: VaultCheckpointContext & VaultCheckpointEpoch,
): Promise<Uint8Array> {
  if (vaultEpochKey.length !== KEY_BYTES) throw new TypeError('Vault checkpoint epoch key must be 32 bytes')
  if (!context.selfGroupId) throw new TypeError('Vault checkpoint self group ID must not be empty')
  assertMlsEpoch(context.epoch)
  const aad = checkpointAad(context)
  const dataKey = crypto.getRandomValues(new Uint8Array(KEY_BYTES))
  const wrapNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const dataNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  try {
    const wrappedDataKey = await aesEncrypt(vaultEpochKey, wrapNonce, aad, dataKey)
    const plaintext = encodeRecoveryArchiveSnapshot(snapshot)
    const ciphertext = await aesEncrypt(dataKey, dataNonce, aad, plaintext)
    return encodeEnvelope({
      version: 3, selfGroupId: context.selfGroupId, epoch: context.epoch,
      wrapNonce, wrappedDataKey, dataNonce, ciphertext, ciphertextHash: sha256(ciphertext), plaintextLength: plaintext.length,
    })
  } finally { dataKey.fill(0) }
}

/** Reads the cleartext epoch header without needing any key -- the caller
 * decides from this whether it can derive the VEK this checkpoint wants
 * before it commits to opening (or reporting a gap for) it. */
export function readVaultCheckpointEpoch(payload: Uint8Array): VaultCheckpointEpoch {
  const envelope = decodeEnvelope(payload)
  return { selfGroupId: envelope.selfGroupId, epoch: envelope.epoch }
}

export async function openVaultCheckpoint(
  vaultEpochKey: Uint8Array,
  payload: Uint8Array,
  context: VaultCheckpointContext,
): Promise<RecoveryArchiveSnapshotV1> {
  if (vaultEpochKey.length !== KEY_BYTES) throw new TypeError('Vault checkpoint epoch key must be 32 bytes')
  const envelope = decodeEnvelope(payload)
  // Built from the envelope's OWN epoch header, so a swapped `selfGroupId` or
  // `epoch` produces a different AAD and fails the unwrap below rather than
  // silently redirecting a reader at another epoch's key.
  const aad = checkpointAad({ ...context, selfGroupId: envelope.selfGroupId, epoch: envelope.epoch })
  if (!equalBytes(envelope.ciphertextHash, sha256(envelope.ciphertext))) throw new TypeError('Vault checkpoint ciphertext hash does not match')
  const dataKey = await aesDecrypt(vaultEpochKey, envelope.wrapNonce, aad, envelope.wrappedDataKey).catch(() => { throw new TypeError('Vault checkpoint key cannot be unwrapped') })
  try {
    const plaintext = await aesDecrypt(dataKey, envelope.dataNonce, aad, envelope.ciphertext).catch(() => { throw new TypeError('Vault checkpoint cannot be decrypted') })
    if (plaintext.length !== envelope.plaintextLength) throw new TypeError('Vault checkpoint plaintext length does not match')
    return decodeRecoveryArchiveSnapshot(plaintext)
  } finally { dataKey.fill(0) }
}

function checkpointAad(context: VaultCheckpointContext & VaultCheckpointEpoch): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault-checkpoint/aad/v3',
    vaultId: context.vaultId,
    coveredSeq: context.coveredSeq,
    selfGroupId: context.selfGroupId,
    epoch: context.epoch,
  })
}

function encodeEnvelope(value: VaultCheckpointEnvelopeV3): Uint8Array {
  assertEnvelope(value)
  return canonicalBytes({ version: value.version, selfGroupId: value.selfGroupId, epoch: value.epoch, wrapNonce: bytesToBase64url(value.wrapNonce), wrappedDataKey: bytesToBase64url(value.wrappedDataKey), dataNonce: bytesToBase64url(value.dataNonce), ciphertext: bytesToBase64url(value.ciphertext), ciphertextHash: bytesToBase64url(value.ciphertextHash), plaintextLength: value.plaintextLength })
}

function decodeEnvelope(bytes: Uint8Array): VaultCheckpointEnvelopeV3 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { throw new TypeError('Vault checkpoint is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Vault checkpoint must be an object')
  const value = input as Record<string, unknown>
  if (Object.keys(value).sort().join() !== ENVELOPE_KEYS || value.version !== 3 || typeof value.selfGroupId !== 'string' || typeof value.epoch !== 'string' || typeof value.wrapNonce !== 'string' || typeof value.wrappedDataKey !== 'string' || typeof value.dataNonce !== 'string' || typeof value.ciphertext !== 'string' || typeof value.ciphertextHash !== 'string' || typeof value.plaintextLength !== 'number') throw new TypeError('Vault checkpoint shape is invalid')
  const envelope: VaultCheckpointEnvelopeV3 = { version: 3, selfGroupId: value.selfGroupId, epoch: value.epoch as MlsEpoch, wrapNonce: base64urlToBytes(value.wrapNonce), wrappedDataKey: base64urlToBytes(value.wrappedDataKey), dataNonce: base64urlToBytes(value.dataNonce), ciphertext: base64urlToBytes(value.ciphertext), ciphertextHash: base64urlToBytes(value.ciphertextHash), plaintextLength: value.plaintextLength }
  assertEnvelope(envelope)
  if (!equalBytes(bytes, encodeEnvelope(envelope))) throw new TypeError('Vault checkpoint is not canonical')
  return envelope
}

function assertEnvelope(value: VaultCheckpointEnvelopeV3): void {
  if (value.version !== 3 || !value.selfGroupId || value.wrapNonce.length !== NONCE_BYTES || value.wrappedDataKey.length !== KEY_BYTES + 16 || value.dataNonce.length !== NONCE_BYTES || value.ciphertext.length === 0 || value.ciphertextHash.length !== 32 || !Number.isSafeInteger(value.plaintextLength) || value.plaintextLength < 0) throw new TypeError('Vault checkpoint envelope is invalid')
  assertMlsEpoch(value.epoch)
}

async function aesEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: buffer(nonce), additionalData: buffer(aad) }, await crypto.subtle.importKey('raw', buffer(key), 'AES-GCM', false, ['encrypt']), buffer(plaintext)))
}
async function aesDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buffer(nonce), additionalData: buffer(aad) }, await crypto.subtle.importKey('raw', buffer(key), 'AES-GCM', false, ['decrypt']), buffer(ciphertext)))
}
function buffer(value: Uint8Array): ArrayBuffer { return Uint8Array.from(value).buffer }
