// Live delivery from ONE mediator over Server-Sent Events (mediator/server.ts's
// `GET /stream`) -- replaces startMediatorPolling's periodic pull for the
// same reason mls/conversation-group-watch.ts replaced mls-ds's own
// poll-based catch-up: found live, 2026-09-01, a Conversation Group's
// 3-message peer-to-peer invite handshake (conversation-group-invite.ts)
// crosses this mediator poll loop THREE separate times (invite delivery,
// join-ready delivery, welcome-ready delivery), so the poll interval's own
// latency (15s default) compounds into tens of seconds of pure waiting
// before a group's founding message can even be sent.
//
// This is a biset-specific extension on top of an otherwise spec-compliant
// DIDComm Pickup 3.0 mediator (mediator-protocol.ts's own header explains
// why WATCH_REQUEST/WATCH_GRANT are biset.md URIs, not didcomm.org ones):
// the pickup family itself is deliberately poll-oriented, for an
// offline-tolerant client that comes back later -- there is no live-push
// concept in the spec to conform to instead.
//
// Deliberately does NOT rely on `EventSource`'s own built-in reconnect
// (would replay a stale token) -- every reconnect attempt, including the
// first connection, re-mints a fresh watch token via `requestWatch` first,
// mirroring conversation-group-watch.ts's identical reasoning.
import { fetchMediatorInfo, type DidCommSender, type MediatorInfo } from './mediator-transport.ts'
import { registerWithMediator } from './mediator-sync.ts'
import { requestWatch, mediatorStreamUrl, unpackQueuedMessage, acknowledgeMessages, type DeliveredMessage } from './mediator-pickup.ts'
import type { ResolveSenderKey } from './crypto.ts'
import { defaultFetch } from '../../client/app/net-fetch.ts'

const RECONNECT_DELAY_MS = 2000

/**
 * True when two spellings name the same mediator endpoint.
 *
 * A delivery handler has to check that the mediator a relationship message
 * names in its own did:peer service (relationship.ts's
 * relationshipMediatorService) really is the mediator the message arrived
 * from -- but the two strings reach that check from different places: one
 * was minted into a did:peer document by the peer, the other comes from
 * this device's own `mediatorUrls` config. A raw `!==` therefore rejects a
 * perfectly matching pair over nothing but a trailing slash or a default
 * port, so compare the parsed URLs instead. An unparseable spelling is not
 * a match (never throws -- the caller's own "does not match" branch is the
 * right answer for a URL that is not a URL).
 */
export function sameMediatorUrl(a: string, b: string): boolean {
  try {
    return new URL(a).toString() === new URL(b).toString()
  } catch {
    return false
  }
}

export interface MediatorWatchOptions {
  mediatorUrl: string
  own: DidCommSender
  resolveSenderKey: ResolveSenderKey
  /** Same contract as startMediatorPolling's onMessage: a throw leaves the
   * message unacknowledged (the mediator keeps it queued -- the ordinary
   * backlog a fresh connection/reconnect re-sends will retry it, there is
   * no separate "redeliver" timer to wait for). */
  onMessage(msg: DeliveredMessage): Promise<void> | void
  /** Called on every connection failure (including token expiry) --
   * informational only; a reconnect is already scheduled by the time this
   * fires. Not called on a deliberate `close()`. */
  onError?(error: unknown): void
  /** DI for tests (and any future non-browser runtime) -- defaults to
   * `globalThis.EventSource`. */
  eventSourceCtor?: typeof EventSource
  fetch?: typeof fetch
  /** DI for tests -- defaults to RECONNECT_DELAY_MS (2s). */
  reconnectDelayMs?: number
}

export interface MediatorWatch {
  close(): void
}

/** Opens a live connection to one mediator's queue for `own.xKid`. */
export function watchMediator(options: MediatorWatchOptions): MediatorWatch {
  const EventSourceCtor = options.eventSourceCtor ?? globalThis.EventSource
  if (!EventSourceCtor) throw new TypeError('watchMediator: no EventSource implementation available')
  const fetchImpl = options.fetch ?? defaultFetch()
  const reconnectDelayMs = options.reconnectDelayMs ?? RECONNECT_DELAY_MS

  let closed = false
  let source: EventSource | undefined
  let retryTimer: ReturnType<typeof setTimeout> | undefined
  let registered = false
  let mediatorInfo: MediatorInfo | undefined

  async function connect(): Promise<void> {
    if (closed) return
    try {
      // Self-heal on every (re)connect, same as startMediatorPolling's own
      // first-tick registration -- a mediator that lost this device's
      // registration (its ConnectionStore reset, say) would otherwise mint
      // a watch token for a kid it's about to decide it doesn't own.
      mediatorInfo = registered ? await fetchMediatorInfo(options.mediatorUrl, fetchImpl) : await registerWithMediator(options.mediatorUrl, options.own, fetchImpl)
      registered = true
      const { token } = await requestWatch(mediatorInfo, options.own, fetchImpl)
      if (closed) return

      const es = new EventSourceCtor(mediatorStreamUrl(options.mediatorUrl, token))
      source = es
      es.onmessage = (event: MessageEvent<string>) => { void handleFrame(event.data) }
      es.onerror = () => {
        es.close()
        if (source === es) source = undefined
        if (closed) return
        options.onError?.(new Error('mediator watch connection lost'))
        retryTimer = setTimeout(() => { void connect() }, reconnectDelayMs)
      }
    } catch (err) {
      if (closed) return
      options.onError?.(err)
      retryTimer = setTimeout(() => { void connect() }, reconnectDelayMs)
    }
  }

  async function handleFrame(data: string): Promise<void> {
    let parsed: unknown
    try {
      parsed = JSON.parse(data)
    } catch {
      options.onError?.(new TypeError('mediator watch: malformed SSE frame (not JSON)'))
      return
    }
    if (typeof parsed !== 'object' || parsed === null) return
    const { id, jwe } = parsed as { id?: unknown; jwe?: unknown }
    if (typeof id !== 'string' || jwe === undefined) return
    const delivered = await unpackQueuedMessage(jwe, id, options.own, options.resolveSenderKey)
    if (!delivered) return
    try {
      await options.onMessage(delivered)
      if (mediatorInfo) await acknowledgeMessages(mediatorInfo, options.own, [delivered.ackId], fetchImpl)
    } catch (e) {
      console.warn(`[didcomm] onMessage failed for ${delivered.ackId}, leaving it queued for retry:`, e instanceof Error ? e.message : e)
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
