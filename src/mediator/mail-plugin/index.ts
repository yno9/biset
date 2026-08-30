// Production entrypoint for the mediator+mail-plugin deploy ("B" in the
// A/B split -- src/mediator/index.ts alone is "A", the same DIDComm core
// with no SMTP surface at all). Runs the identical blind-mediator HTTP
// surface (deployment.ts) plus an SMTP listener that bridges inbound mail
// straight into a Forward-ready DIDComm envelope (bridge.ts) -- no spool,
// relationship credential, or VC layer (2026-08-30 redesign).
import { createMediatorDeployment } from '../deployment.ts'
import { createMailPluginListener } from './listener.ts'

const publicUrl = Bun.env.MEDIATOR_PUBLIC_URL
if (!publicUrl) throw new Error('MEDIATOR_PUBLIC_URL is required')

const databasePath = Bun.env.MEDIATOR_DATABASE_PATH
  ?? (Bun.env.MEDIATOR_DATA_DIR ? `${Bun.env.MEDIATOR_DATA_DIR}/mediator.sqlite` : undefined)
if (!databasePath) throw new Error('MEDIATOR_DATABASE_PATH or MEDIATOR_DATA_DIR is required')

const apexDomain = Bun.env.MAIL_PLUGIN_APEX_DOMAIN
if (!apexDomain) throw new Error('MAIL_PLUGIN_APEX_DOMAIN is required')

const smtpHelloName = Bun.env.MAIL_PLUGIN_SMTP_HELLO_NAME ?? `mail.${apexDomain}`

const deployment = createMediatorDeployment({
  publicUrl,
  databasePath,
  port: envInteger('PORT', 8791, 1, 65_535),
  hostname: Bun.env.MEDIATOR_HOST ?? '127.0.0.1',
  allowedOrigins: new Set((Bun.env.MEDIATOR_ALLOWED_ORIGINS ?? '').split(',').map(value => value.trim()).filter(Boolean)),
  maxRequestBytes: envInteger('MEDIATOR_MAX_REQUEST_BYTES', 2 * 1024 * 1024, 1024, 64 * 1024 * 1024),
  rateLimitPerMinute: envInteger('MEDIATOR_RATE_LIMIT_PER_MINUTE', 3000, 1, 1_000_000),
  maxConnections: envInteger('MEDIATOR_MAX_CONNECTIONS', 10_000, 1, 1_000_000),
  maxKeysPerConnection: envInteger('MEDIATOR_MAX_KEYS_PER_CONNECTION', 32, 1, 1024),
  maxQueueItemsPerRecipient: envInteger('MEDIATOR_MAX_QUEUE_ITEMS', 256, 1, 100_000),
  maxQueueBytesPerRecipient: envInteger('MEDIATOR_MAX_QUEUE_BYTES', 16 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
  maxMessageBytes: envInteger('MEDIATOR_MAX_MESSAGE_BYTES', 1024 * 1024, 1024, 64 * 1024 * 1024),
  queueTtlMs: envInteger('MEDIATOR_QUEUE_TTL_MS', 30 * 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000),
  replayTtlMs: envInteger('MEDIATOR_REPLAY_TTL_MS', 10 * 60 * 1000, 1000, 24 * 60 * 60 * 1000),
  maxReplayIds: envInteger('MEDIATOR_MAX_REPLAY_IDS', 50_000, 100, 10_000_000),
  relayUpstreamUrl: Bun.env.MEDIATOR_RELAY_UPSTREAM_URL,
  serviceName: 'biset-mediator-mail-plugin',
})

const senderIdentity = deployment.store.loadMailPluginIdentity()
const smtpListener = createMailPluginListener({
  hostname: Bun.env.MAIL_PLUGIN_SMTP_HOST ?? '0.0.0.0',
  port: envInteger('MAIL_PLUGIN_SMTP_PORT', 25, 1, 65_535),
  helloName: smtpHelloName,
  apexDomain,
  maxMessageBytes: envInteger('MAIL_PLUGIN_MAX_MESSAGE_BYTES', 25 * 1024 * 1024, 1024, 128 * 1024 * 1024),
  senderIdentity: { kid: senderIdentity.xKid, privateKey: senderIdentity.xPriv },
  ...(Bun.env.MAIL_PLUGIN_TLS_CERT_PATH && Bun.env.MAIL_PLUGIN_TLS_KEY_PATH
    ? { tls: { certPath: Bun.env.MAIL_PLUGIN_TLS_CERT_PATH, keyPath: Bun.env.MAIL_PLUGIN_TLS_KEY_PATH } }
    : {}),
})

console.info(JSON.stringify({
  at: new Date().toISOString(), level: 'info', message: 'mail plugin SMTP listener started',
  port: smtpListener.port, apexDomain, senderKid: senderIdentity.xKid,
}))

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    smtpListener.stop()
    void deployment.shutdown(signal)
  })
}

function envInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = Bun.env[name]
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${name} must be an integer between ${min} and ${max}`)
  }
  return value
}
