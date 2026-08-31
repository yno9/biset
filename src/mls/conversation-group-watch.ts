// Live delivery for a Conversation Group over Server-Sent Events
// (mls-ds/http.ts's `GET /deliveries/stream`) -- the first SSE code in
// biset (there was no prior SSE anywhere in this codebase to mirror).
// Chosen over the deleted `message-notify` push mechanism specifically
// because it needs no DID resolution at all: the client opens this
// connection itself (authenticated the same way every other DS request
// already is, via a signed `deliveries/watch` mint), and the DS just
// writes to whichever connections happen to be open -- see
// conversation-mls-ds.ts's header for why that distinction is the whole
// reason the old push mechanism had to go.
//
// Lives under `src/mls/` (DOM available), never `src/mls-ds/`
// (tsconfig.mls-ds.json has no DOM lib -- `EventSource` is a Web/DOM API
// the server-side deploy unit must never depend on).
//
// This module knows nothing about MLS or Vault -- it delivers raw
// `ConversationLogEntry` objects, exactly as transport-layer as
// mls-ds/client-transport.ts itself. conversation-group-sync.ts's
// `applyConversationGroupLogEntry` is the layer that knows how to apply
// one; wiring this module's `onEntry` into that is the caller's job.
import { base64urlToBytes } from '../protocol/canonical.ts'
import type { ConversationLogEntry, ConversationLogEntryKind } from '../protocol/conversation-mls-ds.ts'
import { conversationDeliveriesWatchSigningBytes } from '../protocol/conversation-mls-ds-signing.ts'
import type { ConversationDeliveriesWatchV1, GroupLocalId } from '../protocol/conversation-mls-ds.ts'
import type { ConversationMlsDeliveryTransport } from '../mls-ds/client-transport.ts'
import type { ConversationGroupSigner } from './conversation-group.ts'

const RECONNECT_DELAY_MS = 2000

export interface ConversationGroupWatchOptions {
  transport: ConversationMlsDeliveryTransport
  groupId: string
  requesterId: GroupLocalId
  sign: ConversationGroupSigner
  /** Resume cursor -- the highest `seq` already applied (0 for a group
   * with no local history yet). Kept current internally from each
   * received entry, so a reconnect resumes from where the last one left
   * off, not from this original value. */
  afterSeq: number
  onEntry(entry: ConversationLogEntry): void
  /** Called on every connection failure (including token expiry) --
   * informational only; a reconnect is already scheduled by the time this
   * fires. Not called on a deliberate `close()`. */
  onError?(error: unknown): void
  /** DI for tests (and any future non-browser runtime) -- defaults to
   * `globalThis.EventSource`. */
  eventSourceCtor?: typeof EventSource
  now?: () => Date
  /** DI for tests -- defaults to `RECONNECT_DELAY_MS` (2s). */
  reconnectDelayMs?: number
}

export interface ConversationGroupWatch {
  close(): void
}

/**
 * Opens a live connection to one Conversation Group's delivery stream.
 * Deliberately does NOT rely on `EventSource`'s own built-in reconnect
 * (which would replay the exact same URL, including a token that may have
 * since expired) -- every reconnect attempt, including the first
 * connection, re-mints a fresh token via `transport.watchDeliveries`
 * first. `EventSource`'s automatic `data:`/`id:` frame parsing is kept
 * (that part has no downside), just not its retry timing/URL reuse.
 */
export function watchConversationGroupDeliveries(options: ConversationGroupWatchOptions): ConversationGroupWatch {
  const EventSourceCtor = options.eventSourceCtor ?? globalThis.EventSource
  if (!EventSourceCtor) throw new TypeError('watchConversationGroupDeliveries: no EventSource implementation available')
  const now = options.now ?? (() => new Date())
  const reconnectDelayMs = options.reconnectDelayMs ?? RECONNECT_DELAY_MS

  let closed = false
  let cursor = options.afterSeq
  let source: EventSource | undefined
  let retryTimer: ReturnType<typeof setTimeout> | undefined

  async function connect(): Promise<void> {
    if (closed) return
    try {
      const watch: Omit<ConversationDeliveriesWatchV1, 'signature'> = {
        version: 1, groupId: options.groupId, requesterId: options.requesterId, requestedAt: now().toISOString(),
      }
      const { token } = await options.transport.watchDeliveries({ ...watch, signature: await options.sign(conversationDeliveriesWatchSigningBytes(watch)) })
      if (closed) return

      const es = new EventSourceCtor(options.transport.streamUrl(token, cursor))
      source = es
      es.onmessage = (event: MessageEvent<string>) => {
        const entry = decodeSseEntry(event.data)
        if (entry.seq <= cursor) return // a reconnect can legitimately re-deliver the tail of what was already seen
        cursor = entry.seq
        options.onEntry(entry)
      }
      es.onerror = () => {
        es.close()
        if (source === es) source = undefined
        if (closed) return
        options.onError?.(new Error('Conversation Group watch connection lost'))
        retryTimer = setTimeout(() => { void connect() }, reconnectDelayMs)
      }
    } catch (err) {
      if (closed) return
      options.onError?.(err)
      retryTimer = setTimeout(() => { void connect() }, reconnectDelayMs)
    }
  }

  void connect()

  return {
    close(): void {
      closed = true
      source?.close()
      source = undefined
      if (retryTimer !== undefined) clearTimeout(retryTimer)
    },
  }
}

function decodeSseEntry(data: string): ConversationLogEntry {
  let parsed: unknown
  try {
    parsed = JSON.parse(data)
  } catch {
    throw new TypeError('Conversation Group watch: malformed SSE frame (not JSON)')
  }
  if (typeof parsed !== 'object' || parsed === null) throw new TypeError('Conversation Group watch: malformed SSE frame')
  const record = parsed as Record<string, unknown>
  if (typeof record.seq !== 'number' || typeof record.kind !== 'string' || typeof record.payload !== 'string' || typeof record.epoch !== 'string' || typeof record.at !== 'string') {
    throw new TypeError('Conversation Group watch: malformed SSE frame')
  }
  return { seq: record.seq, kind: record.kind as ConversationLogEntryKind, payload: base64urlToBytes(record.payload), epoch: record.epoch, at: record.at }
}
