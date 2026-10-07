// Production entrypoint for the standalone blind DIDComm mediator ("A" in
// the mediator+mail-plugin A/B split -- mail-plugin/index.ts is "B", the
// same core (deployment.ts) plus an SMTP bridge). Its only durable state is
// its own did:peer key, verified did:webvh key sets, per-device inboxes,
// opaque JWE queues, and replay IDs in one SQLite database.
import { createMediatorDeployment } from './deployment.ts'

const publicUrl = Bun.env.MEDIATOR_PUBLIC_URL
if (!publicUrl) throw new Error('MEDIATOR_PUBLIC_URL is required')

const databasePath = Bun.env.MEDIATOR_DATABASE_PATH
  ?? (Bun.env.MEDIATOR_DATA_DIR ? `${Bun.env.MEDIATOR_DATA_DIR}/mediator.sqlite` : undefined)
if (!databasePath) throw new Error('MEDIATOR_DATABASE_PATH or MEDIATOR_DATA_DIR is required')

const deployment = createMediatorDeployment({
  publicUrl,
  databasePath,
  // 8790 is the legacy biset-core port in the current deployment.
  port: envInteger('PORT', 8791, 1, 65_535),
  hostname: Bun.env.MEDIATOR_HOST ?? '127.0.0.1',
  allowedOrigins: new Set((Bun.env.MEDIATOR_ALLOWED_ORIGINS ?? '').split(',').map(value => value.trim()).filter(Boolean)),
  maxRequestBytes: envInteger('MEDIATOR_MAX_REQUEST_BYTES', 2 * 1024 * 1024, 1024, 64 * 1024 * 1024),
  rateLimitPerMinute: envInteger('MEDIATOR_RATE_LIMIT_PER_MINUTE', 3000, 1, 1_000_000),
  limits: {
    maxInboxes: envInteger('MEDIATOR_MAX_INBOXES', 30_000, 1, 10_000_000),
    maxDevicesPerDid: envInteger('MEDIATOR_MAX_DEVICES_PER_DID', 3, 1, 64),
    maxQueueItemsPerInbox: envInteger('MEDIATOR_MAX_QUEUE_ITEMS', 1024, 1, 100_000),
    maxQueueBytesPerInbox: envInteger('MEDIATOR_MAX_QUEUE_BYTES', 64 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
    maxMessageBytes: envInteger('MEDIATOR_MAX_MESSAGE_BYTES', 1024 * 1024, 1024, 64 * 1024 * 1024),
    queueTtlMs: envInteger('MEDIATOR_QUEUE_TTL_MS', 30 * 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000),
    dormantAfterMs: envInteger('MEDIATOR_DORMANT_AFTER_MS', 14 * 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000),
    replayTtlMs: envInteger('MEDIATOR_REPLAY_TTL_MS', 10 * 60 * 1000, 1000, 24 * 60 * 60 * 1000),
    maxReplayIds: envInteger('MEDIATOR_MAX_REPLAY_IDS', 50_000, 100, 10_000_000),
  },
  relayUpstreamUrl: Bun.env.MEDIATOR_RELAY_UPSTREAM_URL,
  // MEDIATOR_WEBVH_RESOLVE=0: dial out to nothing; only pushed did:webvh logs are known.
  webvh: { resolve: Bun.env.MEDIATOR_WEBVH_RESOLVE !== '0', refreshSeconds: envInteger('MEDIATOR_WEBVH_REFRESH_SECONDS', 300, 10, 24 * 60 * 60) },
})

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => { void deployment.shutdown(signal) })
}

function envInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = Bun.env[name]
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${name} must be an integer between ${min} and ${max}`)
  }
  return value
}
