import { equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import {
  vaultCoordinatorAckSigningBytes,
  vaultCoordinatorAppendSigningBytes,
  vaultCoordinatorPullSigningBytes,
  type VaultCoordinatorAckV1,
  type VaultCoordinatorAppendV1,
  type VaultCoordinatorPullResult,
  type VaultCoordinatorPullV1,
} from '../protocol/coordinator.ts'
import type { DeliverySeq, DeviceId, IdentityId, MlsEpoch, VaultId, VaultMemberId } from '../protocol/ids.ts'
import type { VaultDeliveryItemV1 } from '../protocol/vault.ts'
import type { VaultDeliveryAckOutboxReader, VaultDeliveryCursorReader, VaultDeliveryOutboxReader, VaultDeliveryOutboxRecord } from './store.ts'
import type { VaultStreamPullResultV2 } from '../protocol/coordinator-stream.ts'

export interface VaultCoordinatorDeliveryTransport {
  append(value: VaultCoordinatorAppendV1): Promise<unknown>
  pull(value: VaultCoordinatorPullV1): Promise<VaultCoordinatorPullResult>
  acknowledge(value: VaultCoordinatorAckV1): Promise<void>
}

export interface VaultCoordinatorMemberSigner {
  readonly memberId: VaultMemberId
  sign(bytes: Uint8Array): Promise<Uint8Array>
}

export interface LegacyVaultDeliveryIngestor {
  ingest(item: VaultDeliveryItemV1): Promise<unknown>
}

export interface CoordinatorDeliveryOutboxFlushResult {
  appendedEntryIds: string[]
  failedEntryId?: string
  failureReason?: string
}

export interface VaultCoordinatorStreamTransport {
  appendStream(value: { version: 2; vaultId: VaultId; appendId: string; payload: Uint8Array; payloadHash: Uint8Array }): Promise<unknown>
  pullStream(value: { version: 2; vaultId: VaultId; after: DeliverySeq }): Promise<VaultStreamPullResultV2>
}

/** v2 has no Coordinator-local member, epoch, recipient fanout, or ACK. */
export async function flushCoordinatorStreamOutbox(
  outbox: VaultDeliveryOutboxReader,
  transport: Pick<VaultCoordinatorStreamTransport, 'appendStream'>,
  identityId: IdentityId,
  vaultId: VaultId,
  limit = 32,
): Promise<CoordinatorDeliveryOutboxFlushResult> {
  const appendedEntryIds: string[] = []
  for (const entry of await outbox.readDeliveryOutbox(identityId, limit)) {
    try {
      assertOutboxEntry(entry, identityId)
      await transport.appendStream({ version: 2, vaultId, appendId: entry.entryId, payload: entry.payload, payloadHash: entry.payloadHash })
      await outbox.removeDeliveryOutbox(identityId, entry.entryId)
      appendedEntryIds.push(entry.entryId)
    } catch (error) {
      await outbox.noteDeliveryOutboxAttempt(identityId, entry.entryId)
      return { appendedEntryIds, failedEntryId: entry.entryId, failureReason: error instanceof Error ? error.message : String(error) }
    }
  }
  return { appendedEntryIds }
}

export async function synchronizeCoordinatorStream(
  store: VaultDeliveryCursorReader & VaultDeliveryAckOutboxReader,
  transport: Pick<VaultCoordinatorStreamTransport, 'pullStream'>,
  ingestor: LegacyVaultDeliveryIngestor,
  identityId: IdentityId,
  recipientDeviceId: DeviceId,
  vaultId: VaultId,
): Promise<{ ingestedSequences: DeliverySeq[]; latestSeq: DeliverySeq }> {
  const after = await store.readDeliveryCursor(identityId, recipientDeviceId)
  const pulled = await transport.pullStream({ version: 2, vaultId, after })
  const ingestedSequences: DeliverySeq[] = []
  for (const item of pulled.items) {
    if (item.vaultId !== vaultId || !equalBytes(sha256Bytes(item.payload), item.payloadHash)) throw new TypeError('Coordinator stream item is invalid')
    await ingestor.ingest({ version: 1, identityId, seq: item.seq, payload: item.payload, payloadHash: item.payloadHash, createdAt: item.createdAt, expiresAt: '9999-12-31T23:59:59.999Z' })
    // The legacy atomic ingest emits an ACK record. v2's global stream needs
    // no per-device acknowledgement, so discard that compatibility artifact.
    await store.removeDeliveryAckOutbox(identityId, recipientDeviceId, item.seq)
    ingestedSequences.push(item.seq)
  }
  return { ingestedSequences, latestSeq: pulled.latestSeq }
}

export type CoordinatorDeliverySyncResult =
  | { kind: 'synced'; ingestedSequences: DeliverySeq[]; pendingAckSequence?: DeliverySeq }
  | { kind: 'restoreRequired'; result: Extract<VaultCoordinatorPullResult, { kind: 'restoreRequired' }>; pendingAckSequence?: DeliverySeq }

/**
 * Transitional client bridge. Public identity remains only the local IndexedDB
 * partition key; it is never serialized into the Coordinator request.
 */
export async function flushCoordinatorDeliveryOutbox(
  outbox: VaultDeliveryOutboxReader,
  transport: Pick<VaultCoordinatorDeliveryTransport, 'append'>,
  signer: VaultCoordinatorMemberSigner,
  identityId: IdentityId,
  vaultId: VaultId,
  groupEpoch: MlsEpoch,
  limit = 32,
  now: () => Date = () => new Date(),
): Promise<CoordinatorDeliveryOutboxFlushResult> {
  const appendedEntryIds: string[] = []
  for (const entry of await outbox.readDeliveryOutbox(identityId, limit)) {
    try {
      assertOutboxEntry(entry, identityId)
      const unsigned = { version: 1 as const, vaultId, appendId: entry.entryId, senderMemberId: signer.memberId, groupEpoch, payloadHash: entry.payloadHash, sentAt: now().toISOString() }
      const signature = await signer.sign(vaultCoordinatorAppendSigningBytes(unsigned))
      assertSignature(signature)
      await transport.append({ ...unsigned, payload: entry.payload, signature })
      await outbox.removeDeliveryOutbox(identityId, entry.entryId)
      appendedEntryIds.push(entry.entryId)
    } catch (error) {
      await outbox.noteDeliveryOutboxAttempt(identityId, entry.entryId)
      return {
        appendedEntryIds,
        failedEntryId: entry.entryId,
        failureReason: error instanceof Error ? error.message : String(error),
      }
    }
  }
  return { appendedEntryIds }
}

/**
 * Reuses the current atomic local ingest transaction while changing only the
 * outer delivery partition from identity/device to vault/member.
 */
export async function synchronizeCoordinatorDelivery(
  store: VaultDeliveryCursorReader & VaultDeliveryAckOutboxReader,
  transport: Pick<VaultCoordinatorDeliveryTransport, 'pull' | 'acknowledge'>,
  ingestor: LegacyVaultDeliveryIngestor,
  signer: VaultCoordinatorMemberSigner,
  identityId: IdentityId,
  recipientDeviceId: DeviceId,
  vaultId: VaultId,
  limit = 32,
  now: () => Date = () => new Date(),
): Promise<CoordinatorDeliverySyncResult> {
  const before = await flushCoordinatorDeliveryAcks(store, transport, signer, identityId, recipientDeviceId, vaultId, limit, now)
  const after = await store.readDeliveryCursor(identityId, recipientDeviceId)
  const unsigned = { version: 1 as const, vaultId, recipientMemberId: signer.memberId, after, requestedAt: now().toISOString() }
  const signature = await signer.sign(vaultCoordinatorPullSigningBytes(unsigned))
  assertSignature(signature)
  const pulled = await transport.pull({ ...unsigned, signature })
  if (pulled.kind === 'restoreRequired') return { kind: 'restoreRequired', result: pulled, ...(before.pendingAckSequence ? { pendingAckSequence: before.pendingAckSequence } : {}) }

  const ingestedSequences: DeliverySeq[] = []
  for (const item of pulled.items) {
    if (item.vaultId !== vaultId) throw new TypeError('Coordinator returned an item for another Vault')
    await ingestor.ingest({ version: 1, identityId, seq: item.seq, payload: item.payload, payloadHash: item.payloadHash, createdAt: item.createdAt, expiresAt: item.expiresAt })
    ingestedSequences.push(item.seq)
  }
  const flushed = await flushCoordinatorDeliveryAcks(store, transport, signer, identityId, recipientDeviceId, vaultId, limit, now)
  return { kind: 'synced', ingestedSequences, ...(flushed.pendingAckSequence ? { pendingAckSequence: flushed.pendingAckSequence } : {}) }
}

export async function flushCoordinatorDeliveryAcks(
  store: VaultDeliveryAckOutboxReader,
  transport: Pick<VaultCoordinatorDeliveryTransport, 'acknowledge'>,
  signer: VaultCoordinatorMemberSigner,
  identityId: IdentityId,
  recipientDeviceId: DeviceId,
  vaultId: VaultId,
  limit = 32,
  now: () => Date = () => new Date(),
): Promise<{ pendingAckSequence?: DeliverySeq }> {
  for (const record of await store.readDeliveryAckOutbox(identityId, recipientDeviceId, limit)) {
    try {
      const unsigned = { version: 1 as const, vaultId, recipientMemberId: signer.memberId, seq: record.seq, payloadHash: record.ack.payloadHash, ackedAt: now().toISOString() }
      const signature = await signer.sign(vaultCoordinatorAckSigningBytes(unsigned))
      assertSignature(signature)
      await transport.acknowledge({ ...unsigned, signature })
      await store.removeDeliveryAckOutbox(identityId, recipientDeviceId, record.seq)
    } catch {
      await store.noteDeliveryAckOutboxAttempt(identityId, recipientDeviceId, record.seq)
      return { pendingAckSequence: record.seq }
    }
  }
  return {}
}

function assertOutboxEntry(entry: VaultDeliveryOutboxRecord, identityId: IdentityId): void {
  if (entry.identityId !== identityId || !entry.entryId || entry.payload.length === 0 || !equalBytes(sha256Bytes(entry.payload), entry.payloadHash)) throw new TypeError('local Coordinator delivery outbox entry is invalid')
}

function assertSignature(signature: Uint8Array): void {
  if (signature.length !== 64) throw new TypeError('Vault member signature must contain 64 bytes')
}
