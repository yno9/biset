import { equalBytes, sha256Bytes } from '../../../shared/protocol/canonical.ts'
import { ingressAckSigningBytes } from '../../../shared/protocol/signing.ts'
import type { IngressAckV1, IngressEnvelopeV1 } from '../../../shared/protocol/ingress.ts'
import type { DeviceId } from '../../../shared/protocol/ids.ts'
import type { VaultDeliveryOutboxRecord, VaultEventRecord, VaultObjectRecord, IngressVaultCommit, IngressReceiptReader } from './store.ts'

export interface IngressAckSigner {
  readonly deviceId: DeviceId
  sign(bytes: Uint8Array): Promise<Uint8Array>
}

/** Protocol-specific decoding/verification happens here, on the endpoint. */
export interface IngressVerifierProjector {
  verifyAndProject(envelope: IngressEnvelopeV1): Promise<{
    objects: VaultObjectRecord[]
    events: VaultEventRecord[]
    projection: unknown
    jmapState: unknown
    checkpointId: string
    deliveryOutbox?: VaultDeliveryOutboxRecord
  }>
}

export interface IngressCommitter {
  commitIngress(input: IngressVaultCommit): Promise<'committed' | 'already-committed'>
}

export interface IngressIngestResult {
  result: 'committed' | 'already-committed'
  ack: IngressAckV1
}

export interface TransportIngressIngestResult {
  result: 'committed' | 'already-committed'
}

/**
 * Converts one externally delivered envelope into one atomic local-vault
 * commit. The callback owns DIDComm/Mail/ActivityPub verification; this
 * orchestration guarantees that an ACK becomes sendable only after that
 * verified projection and its records are durable together.
 */
export async function ingestIngress(
  envelope: IngressEnvelopeV1,
  signer: IngressAckSigner,
  projector: IngressVerifierProjector,
  committer: IngressCommitter,
  now: () => Date = () => new Date(),
): Promise<IngressIngestResult> {
  assertEnvelope(envelope)
  const derived = await projector.verifyAndProject(envelope)
  if (!derived.checkpointId) throw new TypeError('ingress checkpoint ID is required')
  const vaultEventId = derived.events[0]?.id
  if (!vaultEventId) throw new TypeError('ingress projection must create at least one vault event')
  const ackedAt = now().toISOString()
  const unsigned = {
    version: 1 as const,
    ingressId: envelope.ingressId,
    protectedPayloadHash: envelope.protectedPayloadHash,
    recipientDeviceId: signer.deviceId,
    vaultEventId,
    checkpointId: derived.checkpointId,
    ackedAt,
  }
  const signature = await signer.sign(ingressAckSigningBytes(unsigned))
  if (signature.length === 0) throw new TypeError('ingress ACK signature is empty')
  const ack: IngressAckV1 = { ...unsigned, signature }
  const result = await committer.commitIngress({
    identityId: envelope.recipientIdentityId,
    receipt: { identityId: envelope.recipientIdentityId, ingressId: envelope.ingressId, protectedPayloadHash: envelope.protectedPayloadHash.slice(), vaultEventId, checkpointId: derived.checkpointId, committedAt: ackedAt },
    objects: derived.objects,
    events: derived.events,
    projection: derived.projection,
    jmapState: derived.jmapState,
    deliveryOutbox: derived.deliveryOutbox,
    ackOutbox: { identityId: envelope.recipientIdentityId, ingressId: envelope.ingressId, ack, attempts: 0, createdAt: ackedAt },
  })
  return { result, ack }
}

/**
 * Commits ingress from a transport which owns its acknowledgement protocol
 * (for example DIDComm Pickup `messages-received`). No core IngressAck is
 * created. A stable transport ingressId plus the receipt lookup makes a
 * redelivery cheap and lets the caller acknowledge a previously committed
 * item without projecting it twice.
 */
export async function ingestTransportIngress(
  envelope: IngressEnvelopeV1,
  projector: IngressVerifierProjector,
  committer: IngressCommitter & IngressReceiptReader,
  now: () => Date = () => new Date(),
): Promise<TransportIngressIngestResult> {
  assertEnvelope(envelope)
  const existing = await committer.readIngressReceipt(envelope.recipientIdentityId, envelope.ingressId)
  if (existing) {
    if (!equalBytes(existing.protectedPayloadHash, envelope.protectedPayloadHash)) {
      throw new TypeError('transport ingress ID was reused with a different payload')
    }
    return { result: 'already-committed' }
  }
  const derived = await projector.verifyAndProject(envelope)
  if (!derived.checkpointId) throw new TypeError('ingress checkpoint ID is required')
  const vaultEventId = derived.events[0]?.id
  if (!vaultEventId) throw new TypeError('ingress projection must create at least one vault event')
  const committedAt = now().toISOString()
  const result = await committer.commitIngress({
    identityId: envelope.recipientIdentityId,
    receipt: { identityId: envelope.recipientIdentityId, ingressId: envelope.ingressId, protectedPayloadHash: envelope.protectedPayloadHash.slice(), vaultEventId, checkpointId: derived.checkpointId, committedAt },
    objects: derived.objects,
    events: derived.events,
    projection: derived.projection,
    jmapState: derived.jmapState,
    deliveryOutbox: derived.deliveryOutbox,
  })
  return { result }
}

function assertEnvelope(value: IngressEnvelopeV1): void {
  if (!value.recipientIdentityId || !value.ingressId || !equalBytes(sha256Bytes(value.protectedPayload), value.protectedPayloadHash)) {
    throw new TypeError('ingress envelope is invalid')
  }
}
