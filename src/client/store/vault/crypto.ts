import { canonicalBytes, equalBytes } from '../../../protocol/canonical.ts'
import { assertMlsEpoch, type DeviceId, type IdentityId, type MlsEpoch, type SegmentId } from '../../../protocol/ids.ts'
import type { SegmentKeyWrapV1 } from '../../../protocol/vault.ts'

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

/** Identifies which device minted a wrap. Recorded for audit only: unlike
 * MLS membership, nothing here can verify that `grantorDeviceId` was a
 * legitimate holder of the VCK at grant time. Trust rests entirely on the
 * AEAD below -- the VCK is the sole root of trust once a device holds it
 * (see WORKSHEET_vault-sync.md's self-mimi rewrite), so a wrap that
 * decrypts under the current VCK is by construction one only a legitimate
 * holder could have produced. A device-scoped signature could only assert
 * "this specific device holds a still-current key" -- something the
 * decrypt already proves -- and, being tied to one deviceKid, breaks the
 * moment a device re-derives a fresh one (a re-login regenerating its Ed25519
 * leaf) or a genuine sibling grants it: see the 2026-09-15 "SegmentKeyWrap
 * signature is invalid" incident, where MIMI's removal took its whole-room
 * membership verifier with it, leaving a check that could only ever pass
 * for the single device that happened to grant it. */
export interface SegmentGrantor {
  readonly deviceId: DeviceId
}

/**
 * Wraps the random SegmentKey under a current VCK. The caller is
 * responsible for deriving the VCK for the current generation and for
 * checking current membership before granting this wrap.
 */
export async function createSegmentKeyWrap(
  vaultEpochKey: Uint8Array,
  segmentKey: Uint8Array,
  draft: SegmentKeyWrapDraft,
): Promise<SegmentKeyWrapV1> {
  assertKey(vaultEpochKey, 'Vault Epoch Key')
  assertKey(segmentKey, 'SegmentKey')
  assertDraft(draft)

  const nonce = randomNonce()
  const aad = segmentKeyWrapAad(draft)
  const wrappedSegmentKey = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: arrayBuffer(nonce), additionalData: arrayBuffer(aad) },
    await importAesKey(vaultEpochKey, ['encrypt']),
    arrayBuffer(segmentKey),
  ))
  return { version: 1, ...draft, nonce, aad, wrappedSegmentKey }
}

export async function unwrapSegmentKey(
  vaultEpochKey: Uint8Array,
  wrap: SegmentKeyWrapV1,
): Promise<Uint8Array> {
  assertKey(vaultEpochKey, 'Vault Epoch Key')
  assertWrap(wrap)
  if (!equalBytes(wrap.aad, segmentKeyWrapAad(wrap))) throw new TypeError('SegmentKeyWrap AAD does not match metadata')
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

function segmentKeyWrapAad(draft: Pick<SegmentKeyWrapDraft, 'identityId' | 'selfGroupId' | 'segmentId' | 'sourceEpoch' | 'recipientEpoch' | 'grantorDeviceId'>): Uint8Array {
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
  if (wrap.nonce.length !== NONCE_BYTES || wrap.aad.length === 0 || wrap.wrappedSegmentKey.length === 0) {
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
