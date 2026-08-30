// Composes the standalone mediator's durable store, its blind DIDComm
// handler, its HTTP surface, and (optionally) its hop-chain relay poller --
// everything both deploy entrypoints need in common: index.ts (the blind
// mediator alone, "A") and mail-plugin/index.ts (the same mediator plus an
// SMTP bridge, "B"). Factored out so the two entrypoints share this exactly
// rather than index.ts's own bootstrap slowly drifting from a hand-copied
// twin (feedback: unify common logic) -- see tsconfig.mediator.json's own
// header for why mail-plugin/ itself stays a separate typecheck project
// even though its entrypoint imports this file.
import { resolveDidCommSenderKey } from '../didcomm/webvh-resolve.ts'
import { createMediator } from './server.ts'
import { SqliteMediatorStore } from './sqlite-store.ts'
import { IpRateLimiter } from './rate-limit.ts'
import { startRelayPoller, type RelayPollHandle } from './relay-poller.ts'

export interface MediatorDeploymentOptions {
  publicUrl: string
  databasePath: string
  port: number
  hostname?: string
  allowedOrigins?: Set<string>
  maxRequestBytes?: number
  rateLimitPerMinute?: number
  maxConnections?: number
  maxKeysPerConnection?: number
  maxQueueItemsPerRecipient?: number
  maxQueueBytesPerRecipient?: number
  maxMessageBytes?: number
  queueTtlMs?: number
  replayTtlMs?: number
  maxReplayIds?: number
  /** Set to have this mediator poll an upstream one for hop-chained
   * delivery (relay-poller.ts) -- absent means this mediator is a leaf/
   * front-door hop only. */
  relayUpstreamUrl?: string
  serviceName?: string
  log?(level: 'info' | 'error', message: string, fields: Record<string, unknown>): void
}

export interface MediatorDeployment {
  readonly store: SqliteMediatorStore
  readonly mediatorDid: string
  readonly server: ReturnType<typeof Bun.serve>
  shutdown(signal: string): Promise<void>
}

const DEFAULTS = {
  maxRequestBytes: 2 * 1024 * 1024,
  rateLimitPerMinute: 3000,
  maxConnections: 10_000,
  maxKeysPerConnection: 32,
  maxQueueItemsPerRecipient: 256,
  maxQueueBytesPerRecipient: 16 * 1024 * 1024,
  maxMessageBytes: 1024 * 1024,
  queueTtlMs: 30 * 24 * 60 * 60 * 1000,
  replayTtlMs: 10 * 60 * 1000,
  maxReplayIds: 50_000,
}

export function createMediatorDeployment(options: MediatorDeploymentOptions): MediatorDeployment {
  const serviceName = options.serviceName ?? 'biset-didcomm-mediator'
  const log = options.log ?? defaultLog
  const allowedOrigins = options.allowedOrigins ?? new Set<string>()
  const store = SqliteMediatorStore.open(options.databasePath, {
    maxConnections: options.maxConnections ?? DEFAULTS.maxConnections,
    maxKeysPerConnection: options.maxKeysPerConnection ?? DEFAULTS.maxKeysPerConnection,
    maxQueueItemsPerRecipient: options.maxQueueItemsPerRecipient ?? DEFAULTS.maxQueueItemsPerRecipient,
    maxQueueBytesPerRecipient: options.maxQueueBytesPerRecipient ?? DEFAULTS.maxQueueBytesPerRecipient,
    maxMessageBytes: options.maxMessageBytes ?? DEFAULTS.maxMessageBytes,
    queueTtlMs: options.queueTtlMs ?? DEFAULTS.queueTtlMs,
    replayTtlMs: options.replayTtlMs ?? DEFAULTS.replayTtlMs,
    maxReplayIds: options.maxReplayIds ?? DEFAULTS.maxReplayIds,
  })
  const mediator = store.loadIdentity(options.publicUrl)

  const { handle, mediatorDid } = createMediator({
    mediator,
    queue: store,
    connections: store,
    replay: store,
    transaction: store.transaction,
    // Public did:webvh resolution only. No biset-anchor API token, Vault
    // roster, or service-to-service control plane is involved.
    resolveDidWebvh: async (_did, kid) => {
      try { return await resolveDidCommSenderKey(kid) } catch { return null }
    },
  })

  let shuttingDown = false
  const maxRequestBytes = options.maxRequestBytes ?? DEFAULTS.maxRequestBytes
  const requestLimiter = new IpRateLimiter(options.rateLimitPerMinute ?? DEFAULTS.rateLimitPerMinute)
  const server = Bun.serve({
    hostname: options.hostname ?? '127.0.0.1',
    port: options.port,
    maxRequestBodySize: maxRequestBytes,
    async fetch(request) {
      const url = new URL(request.url)
      if (request.method === 'OPTIONS') {
        const origin = request.headers.get('origin')
        if (!origin || !allowedOrigins.has(origin)) return new Response(null, { status: 403 })
        return new Response(null, { status: 204, headers: corsHeaders(origin) })
      }
      const origin = request.headers.get('origin')
      if (origin && !allowedOrigins.has(origin)) return new Response('origin not allowed', { status: 403 })
      if (request.method === 'POST' && url.pathname === '/') {
        const address = request.headers.get('x-forwarded-for')?.split(',', 1)[0]?.trim()
          || server.requestIP(request)?.address
          || 'unknown'
        if (!requestLimiter.allow(address)) {
          return new Response('rate limit exceeded', { status: 429, headers: { 'retry-after': '60' } })
        }
      }
      let response: Response
      if (url.pathname === '/healthz' && request.method === 'GET') {
        response = Response.json({ ok: true, service: serviceName })
      } else if (url.pathname === '/readyz' && request.method === 'GET') {
        try {
          const ready = !shuttingDown && store.ready()
          response = Response.json({ ok: ready, service: serviceName }, { status: ready ? 200 : 503 })
        } catch {
          response = Response.json({ ok: false, service: serviceName }, { status: 503 })
        }
      } else if (url.pathname === '/metrics' && request.method === 'GET') {
        response = new Response(metrics(store.stats()), { headers: { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' } })
      } else {
        response = await handle(request, url) ?? new Response('not found', { status: 404 })
      }
      return origin ? withCors(response, origin) : response
    },
  })

  const expiryTimer = setInterval(() => {
    try { store.expire() } catch (error) { log('error', 'background expiry failed', { error: errorMessage(error) }) }
  }, 60_000)
  expiryTimer.unref()

  // Hop-chaining (2026-08-30 discussion): when this mediator is itself named
  // as an intermediate hop in some recipient's routing.json, an upstream
  // mediator queues Forward-wrapped messages for this relay poller's own kid
  // rather than delivering them directly. Polling it and re-Forwarding into
  // our own `handle` requires no changes to either mediator's dispatch loop
  // -- see relay-poller.ts's own header.
  let relayPoller: RelayPollHandle | undefined
  if (options.relayUpstreamUrl) {
    const relayIdentity = store.loadRelayPollerIdentity()
    relayPoller = startRelayPoller(
      options.relayUpstreamUrl,
      { did: relayIdentity.did, xKid: relayIdentity.xKid, xPriv: relayIdentity.xPriv },
      mediator.xKid,
      async (outbound) => {
        const request = new Request('https://internal.invalid/', {
          method: 'POST',
          headers: { 'content-type': 'application/didcomm-encrypted+json' },
          body: JSON.stringify(outbound),
        })
        const response = await handle(request, new URL(request.url))
        if (!response || response.status !== 202) {
          throw new Error(`relay re-forward was not accepted: HTTP ${response?.status ?? 'null'}`)
        }
      },
      { onError: error => log('error', 'relay poll error', { error: errorMessage(error) }) },
    )
    log('info', 'relay poller started', { upstream: options.relayUpstreamUrl, relayKid: relayIdentity.xKid })
  }

  log('info', 'mediator started', { hostname: options.hostname ?? '127.0.0.1', port: options.port, mediatorDid, databasePath: options.databasePath })

  return {
    store,
    mediatorDid,
    server,
    async shutdown(signal: string): Promise<void> {
      if (shuttingDown) return
      shuttingDown = true
      clearInterval(expiryTimer)
      relayPoller?.stop()
      log('info', 'mediator shutting down', { signal })
      await server.stop(false)
      store.close()
    },
  }
}

function defaultLog(level: 'info' | 'error', message: string, fields: Record<string, unknown>): void {
  const line = JSON.stringify({ at: new Date().toISOString(), level, message, ...fields })
  if (level === 'error') console.error(line)
  else console.info(line)
}

function corsHeaders(origin: string): Headers {
  return new Headers({
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'Content-Type',
    'access-control-max-age': '600',
    'vary': 'Origin',
  })
}

function withCors(response: Response, origin: string): Response {
  const headers = new Headers(response.headers)
  for (const [name, value] of corsHeaders(origin)) headers.set(name, value)
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
}

function metrics(stats: ReturnType<SqliteMediatorStore['stats']>): string {
  const oldestAgeSeconds = stats.oldestQueuedAt === undefined ? 0 : Math.max(0, (Date.now() - stats.oldestQueuedAt) / 1000)
  return [
    '# HELP biset_mediator_connections Registered mediator connections.',
    '# TYPE biset_mediator_connections gauge',
    `biset_mediator_connections ${stats.connections}`,
    '# HELP biset_mediator_connection_keys Registered recipient keys.',
    '# TYPE biset_mediator_connection_keys gauge',
    `biset_mediator_connection_keys ${stats.keys}`,
    '# HELP biset_mediator_queued_messages Opaque JWE messages awaiting ACK.',
    '# TYPE biset_mediator_queued_messages gauge',
    `biset_mediator_queued_messages ${stats.queuedMessages}`,
    '# HELP biset_mediator_queued_bytes Opaque JWE bytes awaiting ACK.',
    '# TYPE biset_mediator_queued_bytes gauge',
    `biset_mediator_queued_bytes ${stats.queuedBytes}`,
    '# HELP biset_mediator_oldest_message_age_seconds Age of the oldest queued message.',
    '# TYPE biset_mediator_oldest_message_age_seconds gauge',
    `biset_mediator_oldest_message_age_seconds ${oldestAgeSeconds}`,
    '',
  ].join('\n')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
