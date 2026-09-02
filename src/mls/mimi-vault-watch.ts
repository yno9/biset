// Live delivery for the Self/Vault MIMI room over Server-Sent Events
// (mimi/http.ts's `GET /v1/mimi/deliveries/stream`) -- the same shape as
// conversation-group-watch.ts's own watch, just against biset-mimi-self
// instead of biset-mls-ds. Deliberately used only as a wake-up signal, not
// as the actual delivery-processing path: `onEntry` fires once per pushed
// entry, but the caller is expected to re-run the EXISTING, already-hardened
// pull-based synchronizeMimiVault (decodeMimiVaultBatch's checkpoint
// collation, the epochTooOld retry, the permanently-undecryptable skip, the
// sentAt-agnostic identity merge -- all of today's fixes) rather than a
// second, parallel decode path built straight on top of individual SSE
// frames. Replaces polling entirely (found live, 2026-09-02: every 10s of
// polling delay was pure dead time on both the sending AND receiving
// device -- this closes both halves at once, not just the sending one
// triggerMimiVaultSync already did).
import { decodeDeliveryEntry } from '../mimi/wire.ts'
import type { MimiCredential, MimiDeliveryEntry } from '../mimi/protocol-types.ts'
import { deliveriesWatchSigningBytes } from '../mimi/authorizer.ts'
import type { MimiClientMode, MimiClientTransport } from './mimi-client-transport.ts'

const RECONNECT_DELAY_MS = 2000

export interface MimiVaultWatchOptions {
  transport: MimiClientTransport
  mode?: MimiClientMode
  roomId: string
  requester: MimiCredential
  sign(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>
  /** Resume cursor -- the highest `seq` already applied. Kept current
   * internally from each received entry, so a reconnect resumes from
   * where the last one left off, not from this original value. */
  afterSeq: number
  onEntry(entry: MimiDeliveryEntry): void
  /** Called on every connection failure (including token expiry) --
   * informational only; a reconnect is already scheduled by the time this
   * fires. Not called on a deliberate `close()`. */
  onError?(error: unknown): void
  /** DI for tests -- defaults to `globalThis.EventSource`. */
  eventSourceCtor?: typeof EventSource
  now?: () => Date
  /** DI for tests -- defaults to `RECONNECT_DELAY_MS` (2s). */
  reconnectDelayMs?: number
}

export interface MimiVaultWatch { close(): void }

/**
 * Opens a live connection to the Self/Vault MIMI room's delivery stream.
 * Deliberately does NOT rely on `EventSource`'s own built-in reconnect
 * (which would replay the exact same URL, including a token that may have
 * since expired) -- every reconnect attempt, including the first
 * connection, re-mints a fresh token via `transport.watchDeliveries` first.
 * `EventSource`'s automatic `data:`/`id:` frame parsing is kept (that part
 * has no downside), just not its retry timing/URL reuse.
 */
export function watchMimiVaultDeliveries(options: MimiVaultWatchOptions): MimiVaultWatch {
  const EventSourceCtor = options.eventSourceCtor ?? globalThis.EventSource
  if (!EventSourceCtor) throw new TypeError('watchMimiVaultDeliveries: no EventSource implementation available')
  const mode = options.mode ?? 'self'
  const now = options.now ?? (() => new Date())
  const reconnectDelayMs = options.reconnectDelayMs ?? RECONNECT_DELAY_MS

  let closed = false
  let cursor = options.afterSeq
  let source: EventSource | undefined
  let retryTimer: ReturnType<typeof setTimeout> | undefined

  async function connect(): Promise<void> {
    if (closed) return
    try {
      const watch = { version: 1 as const, roomId: options.roomId, requester: options.requester, requestedAt: now().toISOString() }
      const { token } = await options.transport.watchDeliveries(mode, { ...watch, signature: await options.sign(deliveriesWatchSigningBytes(watch)) })
      if (closed) return

      const es = new EventSourceCtor(options.transport.streamUrl(mode, token, cursor))
      source = es
      es.onmessage = (event: MessageEvent<string>) => {
        let entry: MimiDeliveryEntry
        try {
          const parsed: unknown = JSON.parse(event.data)
          entry = decodeDeliveryEntry(parsed, 'mimi-vault-watch')
        } catch (err) {
          options.onError?.(err)
          return
        }
        if (entry.seq <= cursor) return // a reconnect can legitimately re-deliver the tail of what was already seen
        cursor = entry.seq
        options.onEntry(entry)
      }
      es.onerror = () => {
        es.close()
        if (source === es) source = undefined
        if (closed) return
        options.onError?.(new Error('MIMI Vault watch connection lost'))
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
