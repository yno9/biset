import { bytesToBase64url, canonicalBytes, equalBytes } from '../protocol/canonical.ts'
import { assertMlsEpoch, type DeviceId, type IdentityId, type MlsEpoch, type SegmentId } from '../protocol/ids.ts'
import type { SegmentKeyWrapV1 } from '../protocol/vault.ts'

const KEY_BYTES = 32
const NONCE_BYTES = 12

export interface SegmentKeyWrapDraft {
  identityId: IdentityId
  selfGroupId: string
  segmentId: SegmentId
  sourceEpoch: MlsEpoch
  recipientEpoch: MlsEpoch
  grantorDeviceId: DeviceId
  grantedAt: string
}

export interface SegmentKeyWrapSigner {
  readonly deviceId: DeviceId
  sign(bytes: Uint8Array): Promise<Uint8Array>
  verify(deviceId: DeviceId, bytes: Uint8Array, signature: Uint8Array): Promise<boolean>
}

export interface SegmentKeyWrapVerifier {
  verify(deviceId: DeviceId, bytes: Uint8Array, signature: Uint8Array): Promise<boolean>
}

/**
 * Wraps the random SegmentKey under a current MLS-derived VEK. The caller is
 * responsible for deriving the VEK from the self-group exporter and for
 * checking current membership before granting this wrap.
 */
export async function createSegmentKeyWrap(
  vaultEpochKey: Uint8Array,
  segmentKey: Uint8Array,
  draft: SegmentKeyWrapDraft,
  signer: SegmentKeyWrapSigner,
): Promise<SegmentKeyWrapV1> {
  assertKey(vaultEpochKey, 'Vault Epoch Key')
  assertKey(segmentKey, 'SegmentKey')
  assertDraft(draft)
  if (draft.grantorDeviceId !== signer.deviceId) throw new TypeError('wrap signer does not match grantor device')

  const nonce = randomNonce()
  const aad = segmentKeyWrapAad(draft)
  const wrappedSegmentKey = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: arrayBuffer(nonce), additionalData: arrayBuffer(aad) },
    await importAesKey(vaultEpochKey, ['encrypt']),
    arrayBuffer(segmentKey),
  ))
  const unsigned = { version: 1 as const, ...draft, nonce, aad, wrappedSegmentKey }
  const signature = await signer.sign(segmentKeyWrapSigningBytes(unsigned))
  if (signature.length === 0) throw new TypeError('SegmentKeyWrap signature must not be empty')
  return { ...unsigned, signature: signature.slice() }
}

export async function unwrapSegmentKey(
  vaultEpochKey: Uint8Array,
  wrap: SegmentKeyWrapV1,
  signer: SegmentKeyWrapVerifier,
): Promise<Uint8Array> {
  assertKey(vaultEpochKey, 'Vault Epoch Key')
  assertWrap(wrap)
  if (!equalBytes(wrap.aad, segmentKeyWrapAad(wrap))) throw new TypeError('SegmentKeyWrap AAD does not match metadata')
  if (!(await signer.verify(wrap.grantorDeviceId, segmentKeyWrapSigningBytes(wrap), wrap.signature))) {
    throw new TypeError('SegmentKeyWrap signature is invalid')
  }
  try {
    const segmentKey = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: arrayBuffer(wrap.nonce), additionalData: arrayBuffer(wrap.aad) },
      await importAesKey(vaultEpochKey, ['decrypt']),
      arrayBuffer(wrap.wrappedSegmentKey),
    ))
    assertKey(segmentKey, 'unwrapped SegmentKey')
    return segmentKey
  } catch (error) {
    if (error instanceof TypeError) throw error
    throw new TypeError('SegmentKeyWrap decryption failed')
  }
}

export function segmentKeyWrapAad(draft: Pick<SegmentKeyWrapDraft, 'identityId' | 'selfGroupId' | 'segmentId' | 'sourceEpoch' | 'recipientEpoch' | 'grantorDeviceId'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault/segment-key-wrap/aad/v1',
    identityId: draft.identityId,
    selfGroupId: draft.selfGroupId,
    segmentId: draft.segmentId,
    sourceEpoch: draft.sourceEpoch,
    recipientEpoch: draft.recipientEpoch,
    grantorDeviceId: draft.grantorDeviceId,
  })
}

export function segmentKeyWrapSigningBytes(
  wrap: Omit<SegmentKeyWrapV1, 'signature'>,
): Uint8Array {
  return canonicalBytes({
    version: wrap.version,
    identityId: wrap.identityId,
    selfGroupId: wrap.selfGroupId,
    segmentId: wrap.segmentId,
    sourceEpoch: wrap.sourceEpoch,
    recipientEpoch: wrap.recipientEpoch,
    nonce: bytesToBase64url(wrap.nonce),
    aad: bytesToBase64url(wrap.aad),
    wrappedSegmentKey: bytesToBase64url(wrap.wrappedSegmentKey),
    grantorDeviceId: wrap.grantorDeviceId,
    grantedAt: wrap.grantedAt,
  })
}

function assertDraft(draft: SegmentKeyWrapDraft): void {
  if (!draft.identityId || !draft.selfGroupId || !draft.segmentId || !draft.grantorDeviceId) {
    throw new TypeError('SegmentKeyWrap draft has empty required fields')
  }
  assertMlsEpoch(draft.sourceEpoch)
  assertMlsEpoch(draft.recipientEpoch)
  if (Number.isNaN(Date.parse(draft.grantedAt))) throw new TypeError('grantedAt must be an ISO date string')
}

function assertWrap(wrap: SegmentKeyWrapV1): void {
  if (wrap.version !== 1) throw new TypeError('unsupported SegmentKeyWrap version')
  assertDraft(wrap)
  if (wrap.nonce.length !== NONCE_BYTES || wrap.aad.length === 0 || wrap.wrappedSegmentKey.length === 0 || wrap.signature.length === 0) {
    throw new TypeError('SegmentKeyWrap fields are invalid')
  }
}

function randomNonce(): Uint8Array {
  const nonce = new Uint8Array(NONCE_BYTES)
  crypto.getRandomValues(nonce)
  return nonce
}

function assertKey(key: Uint8Array, name: string): void {
  if (key.length !== KEY_BYTES) throw new TypeError(`${name} must be 32 bytes`)
}

async function importAesKey(key: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', arrayBuffer(key), 'AES-GCM', false, usages)
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)
  return copy.buffer
}
