import { ingressPullSigningBytes } from '../protocol/signing.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../protocol/ingress.ts'
import type { DeviceId, IdentityId } from '../protocol/ids.ts'
import type { IngressAckOutboxReader } from './store.ts'

export interface IngressPullTransport {
  pull(input: IngressPullV1): Promise<IngressEnvelopeV1[]>
  acknowledge(ack: IngressAckV1): Promise<void>
}

export interface IngressPullSigner {
  readonly deviceId: DeviceId
  sign(bytes: Uint8Array): Promise<Uint8Array>
}

export interface IngressItemIngestor {
  ingest(envelope: IngressEnvelopeV1): Promise<unknown>
}

export interface IngressSyncResult {
  ingestedIngressIds: string[]
  pendingAckIngressId?: string
}

/**
 * Durable external-ingress synchronisation. The mediator's claim lease is
 * acquired by pull; durable ACK outbox work is flushed before and after every
 * pass, so an interrupted network response cannot make a committed mail body
 * disappear from the endpoint's retry queue.
 */
export async function synchronizeIngress(
  outbox: IngressAckOutboxReader,
  transport: IngressPullTransport,
  ingestor: IngressItemIngestor,
  signer: IngressPullSigner,
  identityId: IdentityId,
  recipientDeviceId: DeviceId,
  limit = 32,
  now: () => Date = () => new Date(),
): Promise<IngressSyncResult> {
  if (signer.deviceId !== recipientDeviceId) throw new TypeError('ingress pull signer does not match recipient device')
  const before = await flushIngressAcks(outbox, transport, identityId, recipientDeviceId, limit)
  const unsigned = { version: 1 as const, identityId, recipientDeviceId, requestedAt: now().toISOString() }
  const signature = await signer.sign(ingressPullSigningBytes(unsigned))
  if (signature.length === 0) throw new TypeError('ingress pull signature is empty')
  const ingestedIngressIds: string[] = []
  for (const envelope of await transport.pull({ ...unsigned, signature })) {
    await ingestor.ingest(envelope)
    ingestedIngressIds.push(envelope.ingressId)
  }
  const after = await flushIngressAcks(outbox, transport, identityId, recipientDeviceId, limit)
  return { ingestedIngressIds, ...(after.pendingAckIngressId ?? before.pendingAckIngressId ? { pendingAckIngressId: after.pendingAckIngressId ?? before.pendingAckIngressId } : {}) }
}

async function flushIngressAcks(
  outbox: IngressAckOutboxReader,
  transport: Pick<IngressPullTransport, 'acknowledge'>,
  identityId: IdentityId,
  recipientDeviceId: DeviceId,
  limit = 32,
): Promise<{ pendingAckIngressId?: string }> {
  for (const record of await outbox.readIngressAckOutbox(identityId, recipientDeviceId, limit)) {
    try {
      await transport.acknowledge(record.ack)
      await outbox.removeIngressAckOutbox(identityId, record.ingressId)
    } catch {
      await outbox.noteIngressAckOutboxAttempt(identityId, record.ingressId)
      return { pendingAckIngressId: record.ingressId }
    }
  }
  return {}
}
