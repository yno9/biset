import { fetchMediatorInfo, type DidCommSender, type MediatorInfo } from '../../protocol/didcomm/mediator-transport.ts'
import { acknowledgeMessages, mediatorMultiplexedStreamUrl, requestWatch, unpackQueuedMessage, type DeliveredMessage } from '../../protocol/didcomm/mediator-pickup.ts'
import type { ResolveSenderKey } from '../../protocol/didcomm/crypto.ts'
import { defaultFetch } from '../../protocol/net-fetch.ts'
import { registerWithMediator } from './mediator-sync.ts'

interface Subscription {
  id: symbol
  own: DidCommSender
  recipient: DidCommSender
  resolveSenderKey: ResolveSenderKey
  onMessage(msg: DeliveredMessage): Promise<void> | void
  onError?(error: unknown): void
  fetch: typeof fetch
  mediator?: MediatorInfo
  token?: string
  registered: boolean
  preparing: boolean
}

interface Pool {
  mediatorUrl: string
  subscriptions: Map<symbol, Subscription>
  source?: EventSource
  generation: number
  reconnectTimer?: ReturnType<typeof setTimeout>
  eventSourceCtor: typeof EventSource
}

const pools = new Map<string, Pool>()
const RECONNECT_DELAY_MS = 2_000

export interface MultiplexedMediatorWatchOptions {
  mediatorUrl: string
  own: DidCommSender
  recipient?: DidCommSender
  resolveSenderKey: ResolveSenderKey
  onMessage(msg: DeliveredMessage): Promise<void> | void
  onError?(error: unknown): void
  fetch?: typeof fetch
  eventSourceCtor?: typeof EventSource
}

export interface MultiplexedMediatorWatch { close(): void }

/** Shares one EventSource across every queue on the same mediator origin. */
export function watchMediatorMultiplexed(options: MultiplexedMediatorWatchOptions): MultiplexedMediatorWatch {
  const mediatorUrl = new URL(options.mediatorUrl).toString().replace(/\/$/, '')
  const EventSourceCtor = options.eventSourceCtor ?? globalThis.EventSource
  if (!EventSourceCtor) throw new TypeError('watchMediatorMultiplexed: no EventSource implementation available')
  let pool = pools.get(mediatorUrl)
  if (!pool) {
    pool = { mediatorUrl, subscriptions: new Map(), generation: 0, eventSourceCtor: EventSourceCtor }
    pools.set(mediatorUrl, pool)
  }
  const id = Symbol('mediator-watch')
  const subscription: Subscription = {
    id,
    own: options.own,
    recipient: options.recipient ?? options.own,
    resolveSenderKey: options.resolveSenderKey,
    onMessage: options.onMessage,
    ...(options.onError ? { onError: options.onError } : {}),
    fetch: options.fetch ?? defaultFetch(),
    registered: false,
    preparing: false,
  }
  pool.subscriptions.set(id, subscription)
  void prepare(pool, subscription)

  return {
    close() {
      const current = pools.get(mediatorUrl)
      if (!current?.subscriptions.delete(id)) return
      if (current.subscriptions.size === 0) {
        current.source?.close()
        if (current.reconnectTimer !== undefined) clearTimeout(current.reconnectTimer)
        pools.delete(mediatorUrl)
      } else {
        reopen(current)
      }
    },
  }
}

async function prepare(pool: Pool, subscription: Subscription): Promise<void> {
  if (subscription.preparing || !pool.subscriptions.has(subscription.id)) return
  subscription.preparing = true
  try {
    subscription.mediator = subscription.registered
      ? await fetchMediatorInfo(pool.mediatorUrl, subscription.fetch)
      : await registerWithMediator(pool.mediatorUrl, subscription.own, subscription.fetch, subscription.recipient.xKid)
    subscription.registered = true
    subscription.token = (await requestWatch(
      subscription.mediator,
      subscription.own,
      subscription.fetch,
      subscription.recipient.xKid,
    )).token
    if (pool.subscriptions.has(subscription.id)) reopen(pool)
  } catch (error) {
    subscription.onError?.(error)
    scheduleReconnect(pool)
  } finally {
    subscription.preparing = false
  }
}

function reopen(pool: Pool): void {
  const ready = [...pool.subscriptions.values()].filter(subscription => subscription.token)
  if (ready.length === 0) return
  pool.generation += 1
  const generation = pool.generation
  pool.source?.close()
  const source = new pool.eventSourceCtor(mediatorMultiplexedStreamUrl(pool.mediatorUrl, ready.map(subscription => subscription.token!)))
  pool.source = source
  source.onmessage = event => { void handleFrame(pool, event.data) }
  source.onerror = () => {
    if (pool.source !== source || pool.generation !== generation) return
    source.close()
    pool.source = undefined
    for (const subscription of pool.subscriptions.values()) subscription.onError?.(new Error('mediator watch connection lost'))
    scheduleReconnect(pool)
  }
}

function scheduleReconnect(pool: Pool): void {
  if (pool.reconnectTimer !== undefined || pool.subscriptions.size === 0) return
  pool.reconnectTimer = setTimeout(() => {
    pool.reconnectTimer = undefined
    for (const subscription of pool.subscriptions.values()) {
      subscription.token = undefined
      void prepare(pool, subscription)
    }
  }, RECONNECT_DELAY_MS)
}

async function handleFrame(pool: Pool, data: string): Promise<void> {
  let parsed: { id?: unknown; recipient_kid?: unknown; jwe?: unknown }
  try { parsed = JSON.parse(data) as typeof parsed } catch { return }
  if (typeof parsed.id !== 'string' || typeof parsed.recipient_kid !== 'string' || parsed.jwe === undefined) return
  const subscription = [...pool.subscriptions.values()].find(candidate => candidate.recipient.xKid === parsed.recipient_kid)
  if (!subscription?.mediator) return
  const delivered = await unpackQueuedMessage(parsed.jwe, parsed.id, subscription.recipient, subscription.resolveSenderKey)
  if (!delivered) return
  try {
    await subscription.onMessage(delivered)
    await acknowledgeMessages(subscription.mediator, subscription.own, [delivered.ackId], subscription.fetch, subscription.recipient.xKid)
  } catch (error) {
    console.warn(`[didcomm] onMessage failed for ${delivered.ackId}, leaving it queued for retry:`, error instanceof Error ? error.message : error)
  }
}
