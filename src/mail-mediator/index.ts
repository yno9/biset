// Production entrypoint for the standalone Mail Mediator. Composes:
//   - the DIDComm route-bind/pickup/submit HTTP dispatch (server.ts)
//   - the inbound SMTP listener (smtp-listener.ts)
//   - outbound SMTP submission (submit-outbound.ts, fired from `submit`)
// on one SQLite database (sqlite-store.ts) -- same "one process, one
// deploy unit, zero import from biset-core/roster/vault" shape as
// src/mediator/index.ts, for the same reason (PLAN_biset-mail-mediator.md
// section 2).
import { createMailMediator } from './server.ts'
import { createSmtpMailListener } from './smtp-listener.ts'
import { resolveMailOperationalKid } from './resolve-operational-kid.ts'
import { buildSmtpSubmitOutbound } from './submit-outbound.ts'
import { SqliteMailMediatorStore } from './sqlite-store.ts'

const publicUrl = Bun.env.MAIL_MEDIATOR_PUBLIC_URL
if (!publicUrl) throw new Error('MAIL_MEDIATOR_PUBLIC_URL is required')

const databasePath = Bun.env.MAIL_MEDIATOR_DATABASE_PATH
  ?? (Bun.env.MAIL_MEDIATOR_DATA_DIR ? `${Bun.env.MAIL_MEDIATOR_DATA_DIR}/mail-mediator.sqlite` : undefined)
if (!databasePath) throw new Error('MAIL_MEDIATOR_DATABASE_PATH or MAIL_MEDIATOR_DATA_DIR is required')

const smtpHelloName = Bun.env.MAIL_MEDIATOR_SMTP_HELLO_NAME
if (!smtpHelloName) throw new Error('MAIL_MEDIATOR_SMTP_HELLO_NAME is required')

const httpPort = envInteger('PORT', 8792, 1, 65_535)
const smtpPort = envInteger('MAIL_MEDIATOR_SMTP_PORT', 25, 1, 65_535)
const httpHostname = Bun.env.MAIL_MEDIATOR_HOST ?? '127.0.0.1'
const smtpHostname = Bun.env.MAIL_MEDIATOR_SMTP_HOST ?? '0.0.0.0'
const allowedOrigins = new Set((Bun.env.MAIL_MEDIATOR_ALLOWED_ORIGINS ?? '').split(',').map(v => v.trim()).filter(Boolean))
const maxRequestBytes = envInteger('MAIL_MEDIATOR_MAX_REQUEST_BYTES', 2 * 1024 * 1024, 1024, 64 * 1024 * 1024)
const pickupLeaseMs = envInteger('MAIL_MEDIATOR_PICKUP_LEASE_MS', 5 * 60 * 1000, 1000, 24 * 60 * 60 * 1000)

const smtpTls = Bun.env.MAIL_MEDIATOR_TLS_CERT_PATH && Bun.env.MAIL_MEDIATOR_TLS_KEY_PATH
  ? { certPath: Bun.env.MAIL_MEDIATOR_TLS_CERT_PATH, keyPath: Bun.env.MAIL_MEDIATOR_TLS_KEY_PATH }
  : undefined

const store = SqliteMailMediatorStore.open(databasePath)
const mediator = store.loadIdentity(publicUrl)

const { handle, mediatorDid } = createMailMediator({
  mediator,
  routes: store,
  spool: store,
  submissions: store,
  replay: store,
  transaction: store.transaction,
  resolveMailOperationalKid,
  submitOutbound: buildSmtpSubmitOutbound(smtpHelloName),
  pickupLeaseMs,
})

const smtp = createSmtpMailListener({
  hostname: smtpHostname,
  port: smtpPort,
  helloName: smtpHelloName,
  tls: smtpTls,
  routes: store,
  spool: store,
})

let shuttingDown = false
const server = Bun.serve({
  hostname: httpHostname,
  port: httpPort,
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

    let response: Response
    if (url.pathname === '/healthz' && request.method === 'GET') {
      response = Response.json({ ok: true, service: 'biset-mail-mediator' })
    } else if (url.pathname === '/readyz' && request.method === 'GET') {
      try {
        const ready = !shuttingDown && store.ready()
        response = Response.json({ ok: ready, service: 'biset-mail-mediator' }, { status: ready ? 200 : 503 })
      } catch {
        response = Response.json({ ok: false, service: 'biset-mail-mediator' }, { status: 503 })
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
  try {
    const nowIso = new Date().toISOString()
    store.expireHolders(nowIso)
    store.expireRecords(nowIso)
    store.expireLeases(nowIso)
    store.expireReplay()
  } catch (error) { log('error', 'background expiry failed', { error: errorMessage(error) }) }
}, 60_000)
expiryTimer.unref()

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => { void shutdown(signal) })
}

log('info', 'mail mediator started', { httpHostname, httpPort, smtpHostname, smtpPort, mediatorDid, databasePath })

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return
  shuttingDown = true
  clearInterval(expiryTimer)
  log('info', 'mail mediator shutting down', { signal })
  smtp.stop()
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

function metrics(stats: ReturnType<SqliteMailMediatorStore['stats']>): string {
  const oldestAgeSeconds = stats.oldestPendingCreatedAt === undefined
    ? 0
    : Math.max(0, (Date.now() - Date.parse(stats.oldestPendingCreatedAt)) / 1000)
  return [
    '# HELP biset_mail_mediator_addresses Addresses with a bound route.',
    '# TYPE biset_mail_mediator_addresses gauge',
    `biset_mail_mediator_addresses ${stats.addresses}`,
    '# HELP biset_mail_mediator_holders Registered relationship-kid pickup holders.',
    '# TYPE biset_mail_mediator_holders gauge',
    `biset_mail_mediator_holders ${stats.holders}`,
    '# HELP biset_mail_mediator_pending_spool Spooled messages awaiting pickup ACK.',
    '# TYPE biset_mail_mediator_pending_spool gauge',
    `biset_mail_mediator_pending_spool ${stats.pendingSpool}`,
    '# HELP biset_mail_mediator_oldest_pending_age_seconds Age of the oldest pending spool entry.',
    '# TYPE biset_mail_mediator_oldest_pending_age_seconds gauge',
    `biset_mail_mediator_oldest_pending_age_seconds ${oldestAgeSeconds}`,
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
