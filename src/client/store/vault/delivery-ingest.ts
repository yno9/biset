import { equalBytes, sha256Bytes } from '../../../shared/protocol/canonical.ts'
import { vaultDeliveryAckSigningBytes } from '../../../shared/protocol/signing.ts'
import type { DeviceId, IdentityId } from '../../../shared/protocol/ids.ts'
import type { VaultDeliveryAckV1, VaultDeliveryItemV1 } from '../../../shared/protocol/vault.ts'
import { decodeVaultDeliveryPack, type VaultDeliveryPackV1 } from './delivery-pack.ts'
import type { VaultDeliveryCommit } from './store.ts'

export interface VaultDeliveryAckSigner {
  readonly deviceId: DeviceId
  sign(bytes: Uint8Array): Promise<Uint8Array>
}

/**
 * Performs cryptographic object/event verification and deterministically
 * derives the next local JMAP projection. It must reject before returning
 * when a SegmentKey wrap, event signature, or decrypted mutation is invalid.
 */
export interface VaultDeliveryVerifierProjector {
  verifyAndProject(pack: VaultDeliveryPackV1): Promise<{
    projection: unknown
    jmapState: unknown
    checkpointId: string
  }>
}

export interface VaultDeliveryCommitter {
  commitDelivery(input: VaultDeliveryCommit): Promise<'committed' | 'already-committed'>
}

export interface VaultDeliveryIngestResult {
  result: 'committed' | 'already-committed'
  ack: VaultDeliveryAckV1
}

/**
 * Converts one mediator delivery into a single local durable commit. The
 * caller may hand the returned ACK to the mediator only after this resolves.
 */
export async function ingestVaultDelivery(
  item: VaultDeliveryItemV1,
  signer: VaultDeliveryAckSigner,
  projector: VaultDeliveryVerifierProjector,
  committer: VaultDeliveryCommitter,
  now: () => Date = () => new Date(),
): Promise<VaultDeliveryIngestResult> {
  assertDeliveryItem(item)
  const pack = decodeVaultDeliveryPack(item.payload)
  if (pack.identityId !== item.identityId) throw new TypeError('vault delivery pack identity does not match item')
  const derived = await projector.verifyAndProject(pack)
  if (!derived.checkpointId) throw new TypeError('vault delivery checkpoint ID is required')
  const ackedAt = now().toISOString()
  const unsigned = {
    version: 1 as const,
    identityId: item.identityId,
    seq: item.seq,
    payloadHash: item.payloadHash,
    recipientDeviceId: signer.deviceId,
    checkpointId: derived.checkpointId,
    ackedAt,
  }
  const signature = await signer.sign(vaultDeliveryAckSigningBytes(unsigned))
  if (signature.length === 0) throw new TypeError('vault delivery ACK signature is empty')
  const ack: VaultDeliveryAckV1 = { ...unsigned, signature }
  const result = await committer.commitDelivery({
    identityId: item.identityId,
    receipt: {
      identityId: item.identityId,
      recipientDeviceId: signer.deviceId,
      seq: item.seq,
      payloadHash: item.payloadHash.slice(),
      checkpointId: derived.checkpointId,
      committedAt: ackedAt,
    },
    delivery: item,
    objects: pack.objects,
    events: pack.events,
    keyWraps: pack.keyWraps,
    projection: derived.projection,
    jmapState: derived.jmapState,
    ackOutbox: { identityId: item.identityId, recipientDeviceId: signer.deviceId, seq: item.seq, ack, attempts: 0, createdAt: ackedAt },
  })
  return { result, ack }
}

function assertDeliveryItem(item: VaultDeliveryItemV1): void {
  if (item.version !== 1 || !item.identityId || !item.seq || item.payload.length === 0 || item.payloadHash.length === 0 || !equalBytes(sha256Bytes(item.payload), item.payloadHash)) {
    throw new TypeError('vault delivery item is invalid')
  }
}
