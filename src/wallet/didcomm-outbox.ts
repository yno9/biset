import type { LocalJmapReadModel } from '../local-jmap/gateway.ts'
import type { VaultBackedLocalJmapMutationSink } from '../local-jmap/vault-mutation-sink.ts'
import { sendRelationshipMessage } from '../didcomm/send-message.ts'
import type { ContactKeyV1 } from '../vault/contact-key.ts'
import type { DidCommTransportOutboxRecord } from '../vault/store.ts'

export interface WalletDidCommOutboxStore {
  readDidCommOutbox(identityId: string, limit?: number): Promise<DidCommTransportOutboxRecord[]>
  noteDidCommOutboxAttempt(identityId: string, outboundEventId: DidCommTransportOutboxRecord['outboundEventId'], toDid: string, attemptedAt: string): Promise<void>
  removeDidCommOutbox(identityId: string, outboundEventId: DidCommTransportOutboxRecord['outboundEventId'], toDid: string): Promise<void>
}

export interface WalletDidCommOutboxOptions {
  identityId: string
  store: WalletDidCommOutboxStore
  readModel: Pick<LocalJmapReadModel, 'snapshot' | 'download'>
  mutationSink: Pick<VaultBackedLocalJmapMutationSink, 'commitIntents'>
  ensureContact(toDid: string): Promise<ContactKeyV1>
  send?: (contact: ContactKeyV1, content: string, subject: string | undefined, message: { id: string; sentAt: string }) => Promise<{ ok: boolean; error?: string }>
  onDelivered?: () => void
  onError(error: unknown, item: DidCommTransportOutboxRecord): void
}

export interface WalletDidCommOutbox {
  flush(): Promise<void>
}

/**
 * Retries locally durable 1:1 DIDComm intents. It never removes a row until
 * the authenticated private send succeeds and its local sent-state mutation
 * is durable; a tab close or network failure therefore resumes with the
 * original DIDComm message id on the next boot or retry tick.
 */
export function createWalletDidCommOutbox(options: WalletDidCommOutboxOptions): WalletDidCommOutbox {
  const send = options.send ?? ((contact, content, subject, message) => sendRelationshipMessage(contact, content, subject, undefined, message))
  let flushing = false

  return {
    async flush(): Promise<void> {
      if (flushing) return
      flushing = true
      try {
        const queued = await options.store.readDidCommOutbox(options.identityId)
        for (const item of queued) {
          const snapshot = await options.readModel.snapshot()
          const email = snapshot.emails.find(candidate => candidate.id === item.emailId)
          if (!email?.blobId) {
            options.onError(new Error(`local message ${item.emailId} is missing its body object`), item)
            continue
          }
          await options.store.noteDidCommOutboxAttempt(options.identityId, item.outboundEventId, item.toDid, new Date().toISOString())
          try {
            const contact = await options.ensureContact(item.toDid)
            const content = new TextDecoder().decode(await options.readModel.download(email.blobId))
            const sent = await send(contact, content, email.subject, { id: item.messageId, sentAt: email.sentAt ?? item.createdAt })
            if (!sent.ok) throw new Error(sent.error ?? 'DIDComm send failed')

            const latest = await options.readModel.snapshot()
            const alreadySent = latest.emails.find(candidate => candidate.id === item.emailId)?.mailboxIds.sent === true
            await options.mutationSink.commitIntents([{
              kind: 'transport.result',
              targetIds: [item.emailId],
              payload: { emailId: item.emailId, status: 'accepted', occurredAt: new Date().toISOString(), transport: 'didcomm' },
            }, ...(alreadySent ? [] : [{
              kind: 'mailbox.set' as const,
              targetIds: [item.emailId],
              payload: { emailId: item.emailId, mailboxIds: { sent: true } },
            }])], latest)
            await options.store.removeDidCommOutbox(options.identityId, item.outboundEventId, item.toDid)
            options.onDelivered?.()
          } catch (error) {
            options.onError(error, item)
          }
        }
      } finally {
        flushing = false
      }
    },
  }
}
