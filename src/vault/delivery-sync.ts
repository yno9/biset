import { vaultDeliveryPullSigningBytes } from '../protocol/signing.ts'
import type { DeliveryPullResult, VaultDeliveryAckV1, VaultDeliveryItemV1, VaultDeliveryPullV1 } from '../protocol/vault.ts'
import type { DeviceId, IdentityId } from '../protocol/ids.ts'
import type { VaultDeliveryAckOutboxReader, VaultDeliveryCursorReader } from './store.ts'

export interface VaultDeliveryPullTransport {
  pull(input: VaultDeliveryPullV1): Promise<DeliveryPullResult>
  acknowledge(ack: VaultDeliveryAckV1): Promise<void>
}

export interface VaultDeliveryPullSigner {
  readonly deviceId: DeviceId
  sign(bytes: Uint8Array): Promise<Uint8Array>
}

export interface VaultDeliveryItemIngestor {
  ingest(item: VaultDeliveryItemV1): Promise<unknown>
}

export type VaultDeliverySyncResult =
  | { kind: 'synced'; ingestedSequences: string[]; pendingAckSequence?: string }
  | { kind: 'restoreRequired'; result: Extract<DeliveryPullResult, { kind: 'restoreRequired' }>; pendingAckSequence?: string }

/**
 * One bounded synchronisation pass. Cursor advancement happens only inside
 * the receive-side durable ingest transaction; the sync loop itself has no
 * mutable delivery state and can safely restart after an interrupted wake.
 */
export async function synchronizeVaultDelivery(
  store: VaultDeliveryCursorReader & VaultDeliveryAckOutboxReader,
  transport: VaultDeliveryPullTransport,
  ingestor: VaultDeliveryItemIngestor,
  signer: VaultDeliveryPullSigner,
  identityId: IdentityId,
  recipientDeviceId: DeviceId,
  limit = 32,
  now: () => Date = () => new Date(),
): Promise<VaultDeliverySyncResult> {
  if (signer.deviceId !== recipientDeviceId) throw new TypeError('delivery pull signer does not match recipient device')
  const before = await flushVaultDeliveryAcks(store, transport, identityId, recipientDeviceId, limit)
  const cursor = await store.readDeliveryCursor(identityId, recipientDeviceId)
  const unsigned = { version: 1 as const, identityId, recipientDeviceId, after: cursor, requestedAt: now().toISOString() }
  const signature = await signer.sign(vaultDeliveryPullSigningBytes(unsigned))
  if (signature.length === 0) throw new TypeError('vault delivery pull signature is empty')
  const pulled = await transport.pull({ ...unsigned, signature })
  if (pulled.kind === 'restoreRequired') return { kind: 'restoreRequired', result: pulled, ...(before.pendingAckSequence === undefined ? {} : { pendingAckSequence: before.pendingAckSequence }) }

  const ingestedSequences: string[] = []
  for (const item of pulled.items) {
    await ingestor.ingest(item)
    ingestedSequences.push(item.seq)
  }
  const after = await flushVaultDeliveryAcks(store, transport, identityId, recipientDeviceId, limit)
  return { kind: 'synced', ingestedSequences, ...(after.pendingAckSequence === undefined ? {} : { pendingAckSequence: after.pendingAckSequence }) }
}

async function flushVaultDeliveryAcks(
  store: VaultDeliveryAckOutboxReader,
  transport: Pick<VaultDeliveryPullTransport, 'acknowledge'>,
  identityId: IdentityId,
  recipientDeviceId: DeviceId,
  limit = 32,
): Promise<{ pendingAckSequence?: string }> {
  for (const record of await store.readDeliveryAckOutbox(identityId, recipientDeviceId, limit)) {
    try {
      await transport.acknowledge(record.ack)
      await store.removeDeliveryAckOutbox(identityId, recipientDeviceId, record.seq)
    } catch {
      await store.noteDeliveryAckOutboxAttempt(identityId, recipientDeviceId, record.seq)
      return { pendingAckSequence: record.seq }
    }
  }
  return {}
}
