// Production entrypoint for the standalone blind DIDComm mediator. Its only
// durable state is its own did:peer key, pairwise connection keylists, opaque
// JWE queues, ACK tombstones, and replay IDs in one SQLite database.
import { resolveDidCommSenderKey } from '../didcomm/webvh-resolve.ts'
import { createMediator } from './server.ts'
import { SqliteMediatorStore } from './sqlite-store.ts'
import { IpRateLimiter } from './rate-limit.ts'
import { startRelayPoller, type RelayPollHandle } from './relay-poller.ts'

const publicUrl = Bun.env.MEDIATOR_PUBLIC_URL
if (!publicUrl) throw new Error('MEDIATOR_PUBLIC_URL is required')

const databasePath = Bun.env.MEDIATOR_DATABASE_PATH
  ?? (Bun.env.MEDIATOR_DATA_DIR ? `${Bun.env.MEDIATOR_DATA_DIR}/mediator.sqlite` : undefined)
if (!databasePath) throw new Error('MEDIATOR_DATABASE_PATH or MEDIATOR_DATA_DIR is required')

// 8790 is the legacy biset-core port in the current deployment.
const port = envInteger('PORT', 8791, 1, 65_535)
const hostname = Bun.env.MEDIATOR_HOST ?? '127.0.0.1'
const allowedOrigins = new Set((Bun.env.MEDIATOR_ALLOWED_ORIGINS ?? '').split(',').map(value => value.trim()).filter(Boolean))
const maxRequestBytes = envInteger('MEDIATOR_MAX_REQUEST_BYTES', 2 * 1024 * 1024, 1024, 64 * 1024 * 1024)
const requestLimiter = new IpRateLimiter(envInteger('MEDIATOR_RATE_LIMIT_PER_MINUTE', 3000, 1, 1_000_000))
const store = SqliteMediatorStore.open(databasePath, {
  maxConnections: envInteger('MEDIATOR_MAX_CONNECTIONS', 10_000, 1, 1_000_000),
  maxKeysPerConnection: envInteger('MEDIATOR_MAX_KEYS_PER_CONNECTION', 32, 1, 1024),
  maxQueueItemsPerRecipient: envInteger('MEDIATOR_MAX_QUEUE_ITEMS', 256, 1, 100_000),
  maxQueueBytesPerRecipient: envInteger('MEDIATOR_MAX_QUEUE_BYTES', 16 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
  maxMessageBytes: envInteger('MEDIATOR_MAX_MESSAGE_BYTES', 1024 * 1024, 1024, 64 * 1024 * 1024),
  queueTtlMs: envInteger('MEDIATOR_QUEUE_TTL_MS', 30 * 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000),
  replayTtlMs: envInteger('MEDIATOR_REPLAY_TTL_MS', 10 * 60 * 1000, 1000, 24 * 60 * 60 * 1000),
  maxReplayIds: envInteger('MEDIATOR_MAX_REPLAY_IDS', 50_000, 100, 10_000_000),
})
const mediator = store.loadIdentity(publicUrl)

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
const server = Bun.serve({
  hostname,
  port,
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
      response = Response.json({ ok: true, service: 'biset-didcomm-mediator' })
    } else if (url.pathname === '/readyz' && request.method === 'GET') {
      try {
        const ready = !shuttingDown && store.ready()
        response = Response.json({ ok: ready, service: 'biset-didcomm-mediator' }, { status: ready ? 200 : 503 })
      } catch {
        response = Response.json({ ok: false, service: 'biset-didcomm-mediator' }, { status: 503 })
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
// our own `handle` (below) requires no changes to either mediator's
// dispatch loop -- see relay-poller.ts's own header.
const relayUpstreamUrl = Bun.env.MEDIATOR_RELAY_UPSTREAM_URL
let relayPoller: RelayPollHandle | undefined
if (relayUpstreamUrl) {
  const relayIdentity = store.loadRelayPollerIdentity()
  relayPoller = startRelayPoller(
    relayUpstreamUrl,
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
  log('info', 'relay poller started', { upstream: relayUpstreamUrl, relayKid: relayIdentity.xKid })
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => { void shutdown(signal) })
}

log('info', 'mediator started', { hostname, port, mediatorDid, databasePath })

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return
  shuttingDown = true
  clearInterval(expiryTimer)
  relayPoller?.stop()
  log('info', 'mediator shutting down', { signal })
  await server.stop(false)
  store.close()
}

function envInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = Bun.env[name]
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${name} must be an integer between ${min} and ${max}`)
  }
  return value
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

function log(level: 'info' | 'error', message: string, fields: Record<string, unknown>): void {
  const line = JSON.stringify({ at: new Date().toISOString(), level, message, ...fields })
  if (level === 'error') console.error(line)
  else console.info(line)
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
