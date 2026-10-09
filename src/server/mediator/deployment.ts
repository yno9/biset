// Composes the standalone mediator's durable store, its blind DIDComm
// handler, its HTTP surface, and (optionally) its hop-chain relay poller --
// everything both deploy entrypoints need in common: index.ts (the blind
// mediator alone, "A") and mail-plugin/index.ts (the same mediator plus an
// SMTP bridge, "B"). Factored out so the two entrypoints share this exactly
// rather than index.ts's own bootstrap slowly drifting from a hand-copied
// twin (feedback: unify common logic) -- see tsconfig.mediator.json's own
// header for why mail-plugin/ itself stays a separate typecheck project
// even though its entrypoint imports this file.
import { createMediator } from './server.ts'
import { didCommAccepted, didCommPost } from '../../protocol/didcomm/crypto.ts'
import { SqliteMediatorStore, type SqliteMediatorLimits } from './sqlite-store.ts'
import { IpRateLimiter } from './rate-limit.ts'
import { startRelayPoller, type RelayPollHandle } from './relay-poller.ts'
import { createNetworkWebvhResolver, type WebvhStateResolver } from './webvh-state.ts'
import { peerMediatorIdentity, webMediatorIdentity } from './identity.ts'

export interface MediatorDeploymentOptions {
  publicUrl: string
  databasePath: string
  port: number
  hostname?: string
  allowedOrigins?: Set<string>
  maxRequestBytes?: number
  rateLimitPerMinute?: number
  /** Store limits; unset ones take sqlite-store.ts's defaults. */
  limits?: Partial<SqliteMediatorLimits>
  /** Set to have this mediator poll an upstream one for hop-chained
   * delivery (relay-poller.ts) -- absent means this mediator is a leaf/
   * front-door hop only. */
  relayUpstreamUrl?: string
  /** How this mediator learns a did:webvh's keys (webvh-state.ts). By default
   * it resolves the DID like any DIDComm agent; `resolve: false` makes it
   * dial out to nothing, so only logs pushed to `POST /webvh-log` are known.
   * `refreshSeconds` is how often every did:webvh with an inbox is resolved
   * again (default 300), which is how a device removed from its DID loses its inbox. */
  webvh?: { resolve?: boolean | WebvhStateResolver; refreshSeconds?: number }
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
}

export function createMediatorDeployment(options: MediatorDeploymentOptions): MediatorDeployment {
  const serviceName = options.serviceName ?? 'biset-didcomm-mediator'
  const log = options.log ?? defaultLog
  const allowedOrigins = options.allowedOrigins ?? new Set<string>()
  const store = SqliteMediatorStore.open(options.databasePath, options.limits)
  // A did:web is https by definition: a mediator on any other URL (a local
  // test, a Tor entrance only) is just its did:peer.
  const peerIdentity = store.loadIdentity(options.publicUrl)
  const mediator = new URL(options.publicUrl).protocol === 'https:' ? webMediatorIdentity(peerIdentity, options.publicUrl) : peerMediatorIdentity(peerIdentity)

  let shuttingDown = false
  const maxRequestBytes = options.maxRequestBytes ?? DEFAULTS.maxRequestBytes
  const webvhResolve = options.webvh?.resolve
  const resolveWebvh = webvhResolve === false ? undefined : typeof webvhResolve === 'function' ? webvhResolve : createNetworkWebvhResolver()
  const { handle, live, mediatorDid, refreshWebvh } = createMediator({ mediator, store, maxReceiveBytes: Math.min(maxRequestBytes, store.limits.maxMessageBytes), resolveWebvh })
  const requestLimiter = new IpRateLimiter(options.rateLimitPerMinute ?? DEFAULTS.rateLimitPerMinute)
  const clientAddress = (request: Request) => request.headers.get('x-forwarded-for')?.split(',', 1)[0]?.trim()
    || server.requestIP(request)?.address
    || 'unknown'
  const server = Bun.serve<{ address: string }, never>({
    hostname: options.hostname ?? '127.0.0.1',
    port: options.port,
    maxRequestBodySize: maxRequestBytes,
    // The WebSocket transport (server.ts's `live`): one text frame is one
    // DIDComm message, rate-limited like a POST. Bun pings an idle socket
    // itself, which keeps a quiet live connection open through the proxy.
    websocket: {
      maxPayloadLength: maxRequestBytes,
      idleTimeout: 120,
      async message(ws, data) {
        if (!requestLimiter.allow(ws.data.address)) { ws.close(1008, 'rate limit exceeded'); return }
        await live.message(ws, typeof data === 'string' ? data : new TextDecoder().decode(data))
      },
      close(ws) { live.close(ws) },
    },
    async fetch(request) {
      const url = new URL(request.url)
      if (request.method === 'OPTIONS') {
        const origin = request.headers.get('origin')
        if (!origin || !allowedOrigins.has(origin)) return new Response(null, { status: 403 })
        return new Response(null, { status: 204, headers: corsHeaders(origin) })
      }
      const origin = request.headers.get('origin')
      if (origin && !allowedOrigins.has(origin)) return new Response('origin not allowed', { status: 403 })
      if (request.method === 'GET' && url.pathname === '/' && request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
        if (shuttingDown) return new Response('shutting down', { status: 503 })
        if (server.upgrade(request, { data: { address: clientAddress(request) } })) return undefined
        return new Response('websocket upgrade failed', { status: 400 })
      }
      if (request.method === 'POST' && (url.pathname === '/' || url.pathname === '/webvh-log')) {
        if (!requestLimiter.allow(clientAddress(request))) {
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
  const webvhTimer = resolveWebvh
    ? setInterval(() => {
        refreshWebvh().then(result => {
          if (result.revoked > 0) log('info', 'revoked inboxes of devices their DID no longer lists', result)
        }).catch(error => log('error', 'did:webvh refresh failed', { error: errorMessage(error) }))
      }, (options.webvh?.refreshSeconds ?? 300) * 1000)
    : undefined
  webvhTimer?.unref()

  // Hop-chaining (2026-08-30 discussion): when this mediator is itself named
  // as an intermediate hop in some recipient's DID document, an upstream
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
      mediator.peerKid,
      async (outbound) => {
        const request = new Request('https://internal.invalid/', didCommPost(outbound))
        const response = await handle(request, new URL(request.url))
        if (!response || !didCommAccepted(response.status)) {
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
      if (webvhTimer) clearInterval(webvhTimer)
      relayPoller?.stop()
      log('info', 'mediator shutting down', { signal })
      // Close every connection now, live WebSockets included: a graceful
      // stop waits for them, and a client keeps its socket open until told
      // otherwise -- the restart then hung until systemd killed it (found
      // live 2026-10-03, ~30 s of 502s). Clients reconnect on their own,
      // and nothing is lost: copies stay queued until acknowledged.
      await server.stop(true)
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
    '# HELP biset_mediator_inboxes Registered device inboxes.',
    '# TYPE biset_mediator_inboxes gauge',
    `biset_mediator_inboxes ${stats.inboxes}`,
    '# HELP biset_mediator_recipients Recipient DIDs with at least one inbox.',
    '# TYPE biset_mediator_recipients gauge',
    `biset_mediator_recipients ${stats.recipients}`,
    '# HELP biset_mediator_queued_messages Opaque JWE bodies awaiting ACK by at least one inbox.',
    '# TYPE biset_mediator_queued_messages gauge',
    `biset_mediator_queued_messages ${stats.queuedMessages}`,
    '# HELP biset_mediator_queued_bytes Opaque JWE bytes awaiting ACK.',
    '# TYPE biset_mediator_queued_bytes gauge',
    `biset_mediator_queued_bytes ${stats.queuedBytes}`,
    '# HELP biset_mediator_pending_deliveries Inbox copies awaiting ACK.',
    '# TYPE biset_mediator_pending_deliveries gauge',
    `biset_mediator_pending_deliveries ${stats.pendingDeliveries}`,
    '# HELP biset_mediator_oldest_message_age_seconds Age of the oldest queued message.',
    '# TYPE biset_mediator_oldest_message_age_seconds gauge',
    `biset_mediator_oldest_message_age_seconds ${oldestAgeSeconds}`,
    '',
  ].join('\n')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
