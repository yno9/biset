import { equalBytes, sha256Bytes } from '../shared/protocol/canonical.ts'
import { vaultDeliveryAppendSigningBytes } from '../shared/protocol/signing.ts'
import type { DeviceId, IdentityId } from '../shared/protocol/ids.ts'
import type { VaultDeliveryAppendV1 } from '../shared/protocol/vault.ts'
import type { VaultDeliveryOutboxReader, VaultDeliveryOutboxRecord } from './store.ts'

/** Client-side boundary; HTTP/DIDComm transports will implement this later. */
export interface VaultDeliveryAppendTransport {
  append(input: VaultDeliveryAppendV1): Promise<void>
}

export interface VaultDeliveryAppendSigner {
  readonly deviceId: DeviceId
  sign(bytes: Uint8Array): Promise<Uint8Array>
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
  signer: VaultDeliveryAppendSigner,
  identityId: IdentityId,
  limit = 32,
  now: () => Date = () => new Date(),
): Promise<VaultDeliveryOutboxFlushResult> {
  const appendedEntryIds: string[] = []
  for (const entry of await outbox.readDeliveryOutbox(identityId, limit)) {
    try {
      assertOutboxEntry(entry)
      const unsigned = {
        version: 1,
        identityId: entry.identityId,
        appendId: entry.entryId,
        payload: entry.payload,
        payloadHash: entry.payloadHash,
        senderDeviceId: signer.deviceId,
        sentAt: now().toISOString(),
      } as const
      const signature = await signer.sign(vaultDeliveryAppendSigningBytes(unsigned))
      if (signature.length === 0) throw new TypeError('vault delivery append signature is empty')
      await transport.append({ ...unsigned, signature })
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
