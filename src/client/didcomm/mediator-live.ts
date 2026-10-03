// Live delivery from a mediator: Pickup 3.0 live mode over one WebSocket
// per mediator, shared by every inbox this device watches there (its own
// DID's inbox and each relationship's).
//
// DIDComm v2.1 transports: each WebSocket frame is one DIDComm message, and
// trust comes from its encryption, never from the socket. A socket is
// one-way by default; every request here carries `return_route: "all"`
// (mediator-transport.ts's packMediatorRequest), which is what lets the
// mediator answer -- and, after `live-delivery-change`, push -- on it.
//
// Per inbox, on every (re)connect:
//   1. register over HTTPS (self-heal; idempotent),
//   2. `live-delivery-change {live_delivery: true}` -- new copies are pushed
//      from now on as `delivery` messages,
//   3. the mediator answers with a `status`; if anything is already queued
//      (live mode does not touch the queue, Pickup 3.0), `delivery-request`
//      pulls it, batch by batch, until the status says the inbox is empty.
// Every delivered copy is acked with `messages-received` only after
// `onMessage` returns: the copy stays queued until this device has
// durably taken it, whichever way it arrived.
//
// Live mode ends with the connection (Pickup 3.0), so a reconnect simply
// repeats all of the above.
import { fetchMediatorInfo, packMediatorRequest, unpackMediatorMessage, type MediatorInboxClient, type MediatorInfo } from '../../protocol/didcomm/mediator-transport.ts'
import { inboxStatusOf, mediatorLiveUrl, PermanentDeliveryError, unpackQueuedMessage, type DeliveredMessage } from '../../protocol/didcomm/mediator-pickup.ts'
import { DELIVERY, DELIVERY_REQUEST, LIVE_DELIVERY_CHANGE, MESSAGES_RECEIVED, STATUS } from '../../protocol/didcomm/mediator-protocol.ts'
import { isProblemReport, problemReportError } from '../../protocol/didcomm/problems.ts'
import { parseJwe, type ResolveSenderKey } from '../../protocol/didcomm/crypto.ts'
import { defaultFetch } from '../../protocol/net-fetch.ts'
import { registerWithMediator } from './mediator-sync.ts'

const RECONNECT_DELAY_MS = 2_000
const DELIVERY_BATCH = 10

export interface MediatorLiveOptions {
  mediatorUrl: string
  inbox: MediatorInboxClient
  resolveSenderKey: ResolveSenderKey
  /** A throw leaves the message unacknowledged: it stays queued at the
   * mediator and comes back on the next connection -- except a
   * PermanentDeliveryError, which acknowledges (drops) it. */
  onMessage(msg: DeliveredMessage): Promise<void> | void
  /** Informational; a reconnect is already scheduled when this fires. */
  onError?(error: unknown): void
  /** The mediator dropped copies meant for this inbox while it was dormant
   * or full (its status says `missed`): catch up from a sibling instead. */
  onMissed?(): void
  fetch?: typeof fetch
  /** DI for tests -- defaults to `globalThis.WebSocket`. */
  webSocketCtor?: typeof WebSocket
  reconnectDelayMs?: number
}

export interface MediatorLiveWatch {
  close(): void
  /** Handles everything already queued for this inbox, then resolves. What
   * is left (only copies that failed for a transient reason) stays queued.
   * Rejects if the connection is down or it takes longer than `timeoutMs`. */
  drain(timeoutMs?: number): Promise<void>
}

interface Subscription {
  id: symbol
  inbox: MediatorInboxClient
  resolveSenderKey: ResolveSenderKey
  onMessage(msg: DeliveredMessage): Promise<void> | void
  onError?(error: unknown): void
  onMissed?(): void
  fetch: typeof fetch
  mediator?: MediatorInfo
  registered: boolean
  /** Serializes this inbox's deliveries and acks, in arrival order. */
  queue: Promise<void>
  /** Copies being handled now -- a backlog batch and a live push can
   * carry the same copy. */
  handling: Set<string>
  /** Callers of drain() waiting for this inbox's queue to run dry. */
  drainWaiters: Array<() => void>
  /** Copies already handled and acknowledged. A live push and a backlog
   * batch can carry the same copy before the mediator has applied the ack:
   * it is acknowledged again, never handled twice. Bounded, oldest out. */
  handled: Set<string>
  /** A later retry of copies that failed for a transient reason. */
  retryTimer?: ReturnType<typeof setTimeout>
}

const HANDLED_MEMORY = 1000
/** How soon copies that failed for a transient reason (a seed still on its
 * way, a resolution that failed) are tried again without other traffic. */
const RETRY_DELAY_MS = 30_000

interface Pool {
  mediatorUrl: string
  subscriptions: Map<symbol, Subscription>
  socket?: WebSocket
  reconnectTimer?: ReturnType<typeof setTimeout>
  webSocketCtor: typeof WebSocket
  reconnectDelayMs: number
}

const pools = new Map<string, Pool>()

/** Watches one inbox live, sharing the mediator's socket with every other
 * inbox watched there. */
export function watchMediatorLive(options: MediatorLiveOptions): MediatorLiveWatch {
  const mediatorUrl = new URL(options.mediatorUrl).toString().replace(/\/$/, '')
  const webSocketCtor = options.webSocketCtor ?? globalThis.WebSocket
  if (!webSocketCtor) throw new TypeError('watchMediatorLive: no WebSocket implementation available')
  let pool = pools.get(mediatorUrl)
  if (!pool) {
    pool = { mediatorUrl, subscriptions: new Map(), webSocketCtor, reconnectDelayMs: options.reconnectDelayMs ?? RECONNECT_DELAY_MS }
    pools.set(mediatorUrl, pool)
  }
  const subscription: Subscription = {
    id: Symbol('mediator-live'),
    inbox: options.inbox,
    resolveSenderKey: options.resolveSenderKey,
    onMessage: options.onMessage,
    ...(options.onError ? { onError: options.onError } : {}),
    ...(options.onMissed ? { onMissed: options.onMissed } : {}),
    fetch: options.fetch ?? defaultFetch(),
    registered: false,
    queue: Promise.resolve(),
    handling: new Set(),
    drainWaiters: [],
    handled: new Set(),
  }
  pool.subscriptions.set(subscription.id, subscription)
  if (pool.socket?.readyState === 1) void enable(pool, subscription)
  else if (!pool.socket && pool.reconnectTimer === undefined) connect(pool)

  return {
    close() {
      const current = pools.get(mediatorUrl)
      if (!current?.subscriptions.delete(subscription.id)) return
      if (subscription.retryTimer !== undefined) clearTimeout(subscription.retryTimer)
      if (current.subscriptions.size > 0) {
        if (current.socket?.readyState === 1 && subscription.mediator) {
          send(current, subscription, LIVE_DELIVERY_CHANGE, { recipient_did: subscription.inbox.did, device: subscription.inbox.device, live_delivery: false })
        }
        return
      }
      pools.delete(mediatorUrl)
      if (current.reconnectTimer !== undefined) clearTimeout(current.reconnectTimer)
      const socket = current.socket
      current.socket = undefined
      socket?.close()
    },
    drain(timeoutMs = 15_000) {
      const current = pools.get(mediatorUrl)
      if (!current || current.socket?.readyState !== 1 || !subscription.mediator) return Promise.reject(new Error('mediator live connection is not open'))
      return new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          subscription.drainWaiters = subscription.drainWaiters.filter(waiter => waiter !== done)
          reject(new Error('timed out handling the queued messages'))
        }, timeoutMs)
        const done = () => { clearTimeout(timer); resolve() }
        subscription.drainWaiters.push(done)
        requestDelivery(current, subscription)
      })
    },
  }
}

function requestDelivery(pool: Pool, subscription: Subscription): void {
  subscription.queue = subscription.queue.then(() => send(pool, subscription, DELIVERY_REQUEST, { recipient_did: subscription.inbox.did, device: subscription.inbox.device, limit: DELIVERY_BATCH }))
}

function remember(subscription: Subscription, ackId: string): void {
  subscription.handled.add(ackId)
  if (subscription.handled.size > HANDLED_MEMORY) subscription.handled.delete(subscription.handled.values().next().value!)
}

/** The queue has run dry (or holds only copies that failed transiently). */
function drained(subscription: Subscription): void {
  const waiters = subscription.drainWaiters
  subscription.drainWaiters = []
  for (const done of waiters) done()
}

function connect(pool: Pool): void {
  if (pools.get(pool.mediatorUrl) !== pool || pool.subscriptions.size === 0) return
  let socket: WebSocket
  try {
    socket = new pool.webSocketCtor(mediatorLiveUrl(pool.mediatorUrl))
  } catch (error) {
    lost(pool, undefined, error)
    return
  }
  pool.socket = socket
  socket.onopen = () => { for (const subscription of pool.subscriptions.values()) void enable(pool, subscription) }
  socket.onmessage = event => { if (typeof event.data === 'string') void receive(pool, event.data) }
  socket.onclose = () => lost(pool, socket, new Error('mediator live connection lost'))
}

function lost(pool: Pool, socket: WebSocket | undefined, error: unknown): void {
  if (socket && pool.socket !== socket) return
  pool.socket = undefined
  if (pools.get(pool.mediatorUrl) !== pool) return
  for (const subscription of pool.subscriptions.values()) subscription.onError?.(error)
  if (pool.reconnectTimer !== undefined) return
  pool.reconnectTimer = setTimeout(() => {
    pool.reconnectTimer = undefined
    connect(pool)
  }, pool.reconnectDelayMs)
}

/** Registers (HTTPS) and turns live mode on for one inbox. */
async function enable(pool: Pool, subscription: Subscription): Promise<void> {
  try {
    subscription.mediator = subscription.registered
      ? await fetchMediatorInfo(pool.mediatorUrl, subscription.fetch)
      : await registerWithMediator(pool.mediatorUrl, subscription.inbox, subscription.fetch)
    subscription.registered = true
    if (!pool.subscriptions.has(subscription.id)) return
    send(pool, subscription, LIVE_DELIVERY_CHANGE, { recipient_did: subscription.inbox.did, device: subscription.inbox.device, live_delivery: true })
  } catch (error) {
    subscription.onError?.(error)
    pool.socket?.close()
  }
}

function send(pool: Pool, subscription: Subscription, type: string, body: unknown): void {
  if (!subscription.mediator || pool.socket?.readyState !== 1) return
  pool.socket.send(JSON.stringify(packMediatorRequest(subscription.mediator, subscription.inbox, type, body)))
}

/** One frame from the mediator: authcrypt'd to exactly one of the watched
 * inboxes' keys, which the JWE names. */
async function receive(pool: Pool, data: string): Promise<void> {
  let raw: unknown
  try { raw = JSON.parse(data) } catch { return }
  const kids = new Set((parseJwe(raw)?.recipients ?? []).map(recipient => recipient.header.kid))
  const candidates = [...pool.subscriptions.values()].filter(subscription => subscription.mediator && kids.has(subscription.inbox.xKid))
  if (candidates.length === 0) return
  let message: Awaited<ReturnType<typeof unpackMediatorMessage>>
  try {
    message = await unpackMediatorMessage(candidates[0]!.mediator!, candidates[0]!.inbox, raw)
  } catch (error) {
    candidates[0]!.onError?.(error)
    return
  }
  const body = (message.body ?? {}) as { recipient_did?: unknown; device?: unknown }
  const subscription = candidates.find(candidate => candidate.inbox.did === body.recipient_did && candidate.inbox.device === body.device) ?? candidates[0]!

  if (isProblemReport(message)) {
    const problem = problemReportError(message)
    subscription.onError?.(problem)
    // The mediator no longer has this inbox (its store was reset, or a
    // newer DID log dropped the key): register again on the next connect.
    if (problem.code === 'e.p.req.not_enroll') {
      subscription.registered = false
      pool.socket?.close()
    }
    return
  }
  if (message.type === STATUS) {
    const status = inboxStatusOf(message.body)
    if (status.missed) subscription.onMissed?.()
    if (status.messageCount > 0) requestDelivery(pool, subscription)
    else subscription.queue = subscription.queue.then(() => drained(subscription))
    return
  }
  if (message.type === DELIVERY) {
    const attachments = message.attachments ?? []
    // An answer to this side's delivery-request carries its thread; a live
    // push does not.
    const answered = typeof message.thid === 'string'
    subscription.queue = subscription.queue.then(() => deliver(pool, subscription, attachments, answered))
  }
}

async function deliver(pool: Pool, subscription: Subscription, attachments: NonNullable<Awaited<ReturnType<typeof unpackMediatorMessage>>['attachments']>, answered: boolean): Promise<void> {
  const acked: string[] = []
  for (const attachment of attachments) {
    const ackId = attachment.id
    if (typeof ackId !== 'string' || subscription.handling.has(ackId)) continue
    if (subscription.handled.has(ackId)) { acked.push(ackId); continue }
    subscription.handling.add(ackId)
    try {
      // Undefined: it cannot be opened yet (a transient failure) -- left
      // queued, and retried on the next connection.
      const delivered = await unpackQueuedMessage(attachment.data?.json, ackId, subscription.inbox, subscription.resolveSenderKey)
      if (!delivered) continue
      await subscription.onMessage(delivered)
      acked.push(ackId)
      remember(subscription, ackId)
    } catch (error) {
      if (error instanceof PermanentDeliveryError) {
        // Can never be handled: acknowledge it, so it is not redelivered on
        // every connection until the mediator's retention ends.
        console.warn(`[didcomm] dropping ${ackId}: ${error.message}`)
        acked.push(ackId)
        remember(subscription, ackId)
      } else {
        console.warn(`[didcomm] onMessage failed for ${ackId}, leaving it queued for retry:`, error instanceof Error ? error.message : error)
      }
    } finally {
      subscription.handling.delete(ackId)
    }
  }
  // The mediator answers an ack with a status; a non-empty one pulls the
  // next batch. With nothing acked, what is left can only fail again now --
  // so try it again later, rather than only on the next traffic.
  if (acked.length) send(pool, subscription, MESSAGES_RECEIVED, { recipient_did: subscription.inbox.did, device: subscription.inbox.device, message_id_list: acked })
  else if (answered) drained(subscription)
  if (acked.length < attachments.length && subscription.retryTimer === undefined) {
    subscription.retryTimer = setTimeout(() => {
      subscription.retryTimer = undefined
      if (pools.get(pool.mediatorUrl) === pool && pool.subscriptions.has(subscription.id)) requestDelivery(pool, subscription)
    }, RETRY_DELAY_MS)
  }
}
