import { assertMlsEpoch, type IdentityId, type MlsEpoch } from '../../../protocol/ids.ts'
import { createSegmentKeyWrap, unwrapSegmentKey, type SegmentGrantor } from './crypto.ts'
import type { SegmentKeyWrapReader, SegmentKeyWrapWriter, ActiveVaultSegmentStore } from './store.ts'
import { VAULT_CONTENT_KEY_GROUP_ID, type VaultContentKeyProvider } from './vault-content-key.ts'

/**
 * Durable local completion of a Wallet-approved Vault key rotation. Both VCK
 * generations are retained in the callback session so every SegmentKey can
 * be verified, opened, and granted a next-generation wrap. The operation is
 * idempotent and is resumed on boot until its completion marker is cleared.
 */
export async function rewrapVaultSegmentsForGeneration(input: {
  identityId: IdentityId
  fromGeneration: MlsEpoch
  toGeneration: MlsEpoch
  keys: VaultContentKeyProvider
  segments: ActiveVaultSegmentStore
  wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter
  signer: SegmentGrantor
  now?: () => Date
}): Promise<number> {
  const { identityId, fromGeneration, toGeneration, keys, segments, wraps, signer } = input
  assertMlsEpoch(fromGeneration)
  assertMlsEpoch(toGeneration)
  if (BigInt(toGeneration) !== BigInt(fromGeneration) + 1n) throw new TypeError('Vault key rotation must advance exactly one generation')
  const oldKey = await keys.keyForGeneration(identityId, fromGeneration)
  const nextKey = await keys.keyForGeneration(identityId, toGeneration)
  if (!oldKey || oldKey.length !== 32 || !nextKey || nextKey.length !== 32) throw new Error('Both Vault Content Key generations are required; reconnect your did.md Wallet')
  const now = input.now ?? (() => new Date())
  let rewrapped = 0
  try {
    for (const segment of await segments.allSegments(identityId)) {
      const existing = await wraps.readSegmentKeyWrap(identityId, segment.segmentId, fromGeneration)
      if (!existing) throw new Error(`SegmentKeyWrap for Vault generation ${fromGeneration} is unavailable; restore the Vault before rotating its key`)
      if (existing.selfGroupId !== VAULT_CONTENT_KEY_GROUP_ID || existing.recipientEpoch !== fromGeneration) throw new TypeError('SegmentKeyWrap does not belong to the current Vault Content Key generation')
      const segmentKey = await unwrapSegmentKey(oldKey, existing)
      try {
        const replacement = await createSegmentKeyWrap(nextKey, segmentKey, {
          identityId,
          selfGroupId: VAULT_CONTENT_KEY_GROUP_ID,
          segmentId: segment.segmentId,
          sourceEpoch: fromGeneration,
          recipientEpoch: toGeneration,
          grantorDeviceId: signer.deviceId,
          grantedAt: now().toISOString(),
        })
        await wraps.writeSegmentKeyWrap(replacement)
        await segments.recordSegmentRewrapped(identityId, segment.segmentId, toGeneration, VAULT_CONTENT_KEY_GROUP_ID)
        rewrapped += 1
      } finally { segmentKey.fill(0) }
    }
    return rewrapped
  } finally {
    oldKey.fill(0)
    nextKey.fill(0)
  }
}
