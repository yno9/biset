// Production entrypoint for the standalone blind DIDComm mediator. Mail is a
// separate service (didmail) the mediator knows nothing of. Its only durable
// state is its own did:peer key, verified did:webvh key sets, per-device
// inboxes, opaque JWE queues, and replay IDs in one SQLite database.
import { createMediatorDeployment } from './deployment.ts'
import { openLiveMediatorLimits } from './settings.ts'
import { createMediatorAdminApi } from './admin-api.ts'

const publicUrl = process.env.MEDIATOR_PUBLIC_URL
if (!publicUrl) throw new Error('MEDIATOR_PUBLIC_URL is required')

const databasePath = process.env.MEDIATOR_DATABASE_PATH
  ?? (process.env.MEDIATOR_DATA_DIR ? `${process.env.MEDIATOR_DATA_DIR}/mediator.sqlite` : undefined)
if (!databasePath) throw new Error('MEDIATOR_DATABASE_PATH or MEDIATOR_DATA_DIR is required')

const limits = {
  maxInboxes: envInteger('MEDIATOR_MAX_INBOXES', 30_000, 1, 10_000_000),
  maxDevicesPerDid: envInteger('MEDIATOR_MAX_DEVICES_PER_DID', 3, 1, 64),
  maxQueueItemsPerInbox: envInteger('MEDIATOR_MAX_QUEUE_ITEMS', 1024, 1, 100_000),
  maxQueueBytesPerInbox: envInteger('MEDIATOR_MAX_QUEUE_BYTES', 64 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
}
const rateLimitPerMinute = envInteger('MEDIATOR_RATE_LIMIT_PER_MINUTE', 3000, 1, 1_000_000)
const newInboxesPerAddressPerHour = envInteger('MEDIATOR_NEW_INBOXES_PER_ADDRESS_PER_HOUR', 60, 1, 1_000_000)
// The numbers v2 admin can change while the mediator runs start from the environment's; with no admin, those stand.
const live = openLiveMediatorLimits({ requestsPerMinute: rateLimitPerMinute, newInboxesPerAddressPerHour, limits }, { onProblem: message => console.warn(`[settings] ${message}`) })

const deployment = await createMediatorDeployment({
  live,
  admin: store => createMediatorAdminApi({ store }),
  publicUrl,
  databasePath,
  // 8790 is the legacy biset-core port in the current deployment.
  port: envInteger('PORT', 8791, 1, 65_535),
  hostname: process.env.MEDIATOR_HOST ?? '127.0.0.1',
  allowedOrigins: new Set((process.env.MEDIATOR_ALLOWED_ORIGINS ?? '').split(',').map(value => value.trim()).filter(Boolean)),
  maxRequestBytes: envInteger('MEDIATOR_MAX_REQUEST_BYTES', 2 * 1024 * 1024, 1024, 64 * 1024 * 1024),
  rateLimitPerMinute,
  limits: {
    ...limits,
    maxMessageBytes: envInteger('MEDIATOR_MAX_MESSAGE_BYTES', 1024 * 1024, 1024, 64 * 1024 * 1024),
    queueTtlMs: envInteger('MEDIATOR_QUEUE_TTL_MS', 30 * 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000),
    dormantAfterMs: envInteger('MEDIATOR_DORMANT_AFTER_MS', 14 * 24 * 60 * 60 * 1000, 60_000, 365 * 24 * 60 * 60 * 1000),
    replayTtlMs: envInteger('MEDIATOR_REPLAY_TTL_MS', 10 * 60 * 1000, 1000, 24 * 60 * 60 * 1000),
    maxReplayIds: envInteger('MEDIATOR_MAX_REPLAY_IDS', 50_000, 100, 10_000_000),
  },
  // MEDIATOR_ALLOWED_DID_DOMAINS=did.md,biset.md: only a did:webvh on these domains (or below) may register.
  // Unset: any DID whose owner can prove it. A did:peer is not limited by this.
  registration: {
    allowedDidDomains: (process.env.MEDIATOR_ALLOWED_DID_DOMAINS ?? '').split(',').map(value => value.trim().toLowerCase()).filter(Boolean),
    newInboxesPerAddressPerHour,
  },
  relayUpstreamUrl: process.env.MEDIATOR_RELAY_UPSTREAM_URL,
  // MEDIATOR_WEBVH_RESOLVE=0: dial out to nothing; only pushed did:webvh logs are known.
  webvh: { resolve: process.env.MEDIATOR_WEBVH_RESOLVE !== '0', refreshSeconds: envInteger('MEDIATOR_WEBVH_REFRESH_SECONDS', 300, 10, 24 * 60 * 60) },
})

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => { void deployment.shutdown(signal) })
}

function envInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name]
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${name} must be an integer between ${min} and ${max}`)
  }
  return value
}
