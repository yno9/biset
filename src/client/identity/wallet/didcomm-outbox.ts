import type { LocalJmapReadModel } from '../../store/projection/gateway.ts'
import type { VaultBackedLocalJmapMutationSink } from '../../store/projection/vault-mutation-sink.ts'
import { sendGroupChatMessage, sendRelationshipMessage } from '../../didcomm/send-message.ts'
import { parseDidCommGroupAddress } from '../../didcomm/group-chat.ts'
import type { ContactKeyV1 } from '../../store/vault/contact-key.ts'
import type { DidCommTransportOutboxRecord } from '../../store/vault/store.ts'

interface WalletDidCommOutboxStore {
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
  send?: (contact: ContactKeyV1, content: string, subject: string | undefined, message: { id: string; sentAt: string }, threadId: string) => Promise<{ ok: boolean; error?: string }>
  onDelivered?: () => void
  onError(error: unknown, item: DidCommTransportOutboxRecord): void
}

export interface WalletDidCommOutbox {
  /** With a recipient, flush only that recipient's durable rows. Group
   * creation uses this after its corresponding invite has been accepted so
   * another member's content can never overtake their invite. */
  flush(toDid?: string): Promise<void>
}

/**
 * Retries locally durable 1:1 DIDComm intents. It never removes a row until
 * the authenticated private send succeeds and its local sent-state mutation
 * is durable; a tab close or network failure therefore resumes with the
 * original DIDComm message id on the next boot or retry tick.
 */
export function createWalletDidCommOutbox(options: WalletDidCommOutboxOptions): WalletDidCommOutbox {
  const send = options.send ?? ((contact, content, subject, message, threadId) => threadId.startsWith('didcomm-group:')
    ? sendGroupChatMessage(contact, { groupId: parseDidCommGroupAddress(threadId), content, ...(subject ? { subject } : {}) }, undefined, message)
    : sendRelationshipMessage(contact, content, subject, undefined, message))
  const inFlight = new Set<string>()

  return {
    async flush(toDid?: string): Promise<void> {
      const queued = (await options.store.readDidCommOutbox(options.identityId))
        .filter(item => toDid === undefined || item.toDid === toDid)
      await Promise.allSettled(queued.map(async item => {
        const key = `${item.outboundEventId}\u0000${item.toDid}`
        if (inFlight.has(key)) return
        inFlight.add(key)
        try {
          // One row stuck in a long relationship wait or mediator request
          // must not delay later rows. This was found live when the former
          // process-wide `flushing` flag stayed set behind one stalled send.
          const snapshot = await options.readModel.snapshot()
          const email = snapshot.emails.find(candidate => candidate.id === item.emailId)
          const blobId = item.blobId ?? email?.blobId
          if (!blobId) {
            options.onError(new Error(`local message ${item.emailId} is missing its body object`), item)
            return
          }
          await options.store.noteDidCommOutboxAttempt(options.identityId, item.outboundEventId, item.toDid, new Date().toISOString())
          try {
            const metadata = email ?? await recoverMessageMetadata(item, options.readModel)
            if (!metadata) throw new Error(`local message ${item.emailId} is missing its metadata object`)
            const contact = await options.ensureContact(item.toDid)
            const content = new TextDecoder().decode(await options.readModel.download(blobId))
            const sent = await send(contact, content, metadata.subject, { id: item.messageId, sentAt: metadata.sentAt ?? item.createdAt }, metadata.threadId)
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
        } finally { inFlight.delete(key) }
      }))
    },
  }
}

async function recoverMessageMetadata(
  item: DidCommTransportOutboxRecord,
  readModel: Pick<LocalJmapReadModel, 'download'>,
): Promise<{ threadId: string; subject?: string; sentAt?: string } | null> {
  if (item.threadId) return { threadId: item.threadId, ...(item.subject ? { subject: item.subject } : {}), ...(item.sentAt ? { sentAt: item.sentAt } : {}) }
  if (!item.metadataBlobId) return null
  let decoded: unknown
  try { decoded = JSON.parse(new TextDecoder().decode(await readModel.download(item.metadataBlobId))) } catch { return null }
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) return null
  const payload = (decoded as Record<string, unknown>).payload
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return null
  const email = (payload as Record<string, unknown>).email
  if (email === null || typeof email !== 'object' || Array.isArray(email)) return null
  const value = email as Record<string, unknown>
  if (value.id !== item.emailId || typeof value.threadId !== 'string' || !value.threadId || (item.blobId && value.blobId !== item.blobId)) return null
  if (value.subject !== undefined && typeof value.subject !== 'string') return null
  if (value.sentAt !== undefined && typeof value.sentAt !== 'string') return null
  return { threadId: value.threadId, ...(typeof value.subject === 'string' ? { subject: value.subject } : {}), ...(typeof value.sentAt === 'string' ? { sentAt: value.sentAt } : {}) }
}
