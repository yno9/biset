import { equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import type { IdentityId } from '../protocol/ids.ts'
import type { VaultDeliveryAppendV1 } from '../protocol/vault.ts'
import type { VaultDeliveryOutboxReader, VaultDeliveryOutboxRecord } from './store.ts'

/** Client-side boundary; HTTP/DIDComm transports will implement this later. */
export interface VaultDeliveryAppendTransport {
  append(input: VaultDeliveryAppendV1): Promise<void>
}

export interface VaultDeliveryOutboxFlushResult {
  appendedEntryIds: string[]
  failedEntryId?: string
}

/**
 * Sends local shared-vault payloads in causal order. A failed first entry
 * stops the batch: later events may name it as a parent. `appendId` makes a
 * retry safe if the network lost a successful mediator response.
 */
export async function flushVaultDeliveryOutbox(
  outbox: VaultDeliveryOutboxReader,
  transport: VaultDeliveryAppendTransport,
  identityId: IdentityId,
  limit = 32,
): Promise<VaultDeliveryOutboxFlushResult> {
  const appendedEntryIds: string[] = []
  for (const entry of await outbox.readDeliveryOutbox(identityId, limit)) {
    try {
      assertOutboxEntry(entry)
      await transport.append({
        version: 1,
        identityId: entry.identityId,
        appendId: entry.entryId,
        payload: entry.payload,
        payloadHash: entry.payloadHash,
      })
      await outbox.removeDeliveryOutbox(identityId, entry.entryId)
      appendedEntryIds.push(entry.entryId)
    } catch {
      await outbox.noteDeliveryOutboxAttempt(identityId, entry.entryId)
      return { appendedEntryIds, failedEntryId: entry.entryId }
    }
  }
  return { appendedEntryIds }
}

function assertOutboxEntry(entry: VaultDeliveryOutboxRecord): void {
  if (!entry.identityId || !entry.entryId || entry.payload.length === 0 || !equalBytes(sha256Bytes(entry.payload), entry.payloadHash)) {
    throw new TypeError('local vault delivery outbox entry is invalid')
  }
}
