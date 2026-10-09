import type { LocalJmapReadModel } from '../../store/projection/gateway.ts'
import type { VaultBackedLocalJmapMutationSink } from '../../store/projection/vault-mutation-sink.ts'
import { sendDidCommMessage } from '../../didcomm/send-message.ts'
import { parseDidCommGroupAddress } from '../../didcomm/group-chat.ts'
import { audienceOfCopy, type DidCommRoute } from '../../didcomm/did-rotation.ts'
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
  /** What a message to the counterparty whose public DID this is goes from
   * and to (did-rotation.ts's chooseRoute): the front door, or the DIDs the
   * conversation moved to. Asked at each attempt, so a retry follows a move. */
  route(publicDid: string): Promise<DidCommRoute>
  send?: (toDid: string, content: string, message: OutboundChatMessage) => Promise<{ ok: boolean; error?: string }>
  onDelivered?: (item: DidCommTransportOutboxRecord) => void
  onError(error: unknown, item: DidCommTransportOutboxRecord): void
}

/** What a queued row sends: the message as it was written, so a retry
 * carries the same DIDComm id and time. A group message also names its
 * conversation (`thid`) and every participant (`audience`); a 1:1 reply, the
 * message it answers (`thid`). */
interface OutboundChatMessage {
  id: string
  sentAt: string
  subject?: string
  thid?: string
  audience?: string[]
}

export interface WalletDidCommOutbox {
  /** With a recipient, flush only that recipient's durable rows. */
  flush(toDid?: string): Promise<void>
}

/**
 * Retries locally durable DIDComm chat intents, one row per recipient. It
 * never removes a row until the send succeeds and its local sent-state
 * mutation is durable; a tab close or network failure therefore resumes with
 * the original DIDComm message id on the next boot or retry tick.
 */
export function createWalletDidCommOutbox(options: WalletDidCommOutboxOptions): WalletDidCommOutbox {
  const send = options.send ?? (async (publicDid, content, message) => {
    const route = await options.route(publicDid)
    return sendDidCommMessage(route.toDid, content, {
      fromKid: route.fromKid, x25519PrivateKey: route.x25519PrivateKey, ...(route.fromPrior ? { fromPrior: route.fromPrior } : {}),
      id: message.id, sentAt: message.sentAt,
      ...(message.subject ? { subject: message.subject } : {}),
      ...(message.thid ? { thid: message.thid } : {}),
      ...(message.audience ? { audience: audienceOfCopy(message.audience, publicDid, route.toDid) } : {}),
    })
  })
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
          // One row stuck in a slow mediator request must not delay later rows. This was found live when the former
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
            const metadata = email ? { threadId: email.threadId, subject: email.subject, sentAt: email.sentAt, to: email.to?.map(address => address.email).filter((value): value is string => typeof value === 'string') } : await recoverMessageMetadata(item, options.readModel)
            if (!metadata) throw new Error(`local message ${item.emailId} is missing its metadata object`)
            const content = new TextDecoder().decode(await options.readModel.download(blobId))
            const group = metadata.threadId.startsWith('didcomm-group:')
            // A 1:1 reply names the message it answers by its DIDComm id (a
            // mail bridge turns it into In-Reply-To, didmail PROTOCOL.md §6.2).
            const answered = !group && email?.inReplyTo ? snapshot.emails.find(candidate => candidate.id === email.inReplyTo)?.messageId : undefined
            const sent = await send(item.toDid, content, {
              id: item.messageId, sentAt: metadata.sentAt ?? item.createdAt,
              ...(metadata.subject ? { subject: metadata.subject } : {}),
              ...(group ? { thid: parseDidCommGroupAddress(metadata.threadId), audience: metadata.to ?? [item.toDid] } : answered ? { thid: answered } : {}),
            })
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
            options.onDelivered?.(item)
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
): Promise<{ threadId: string; subject?: string; sentAt?: string; to?: string[] } | null> {
  if (item.threadId && !item.threadId.startsWith('didcomm-group:')) return { threadId: item.threadId, ...(item.subject ? { subject: item.subject } : {}), ...(item.sentAt ? { sentAt: item.sentAt } : {}) }
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
  const to = Array.isArray(value.to) ? value.to.map(address => (address as { email?: unknown })?.email).filter((email): email is string => typeof email === 'string') : undefined
  return { threadId: value.threadId, ...(typeof value.subject === 'string' ? { subject: value.subject } : {}), ...(typeof value.sentAt === 'string' ? { sentAt: value.sentAt } : {}), ...(to?.length ? { to } : {}) }
}
