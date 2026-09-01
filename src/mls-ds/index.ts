// Production entrypoint for the standalone Conversation Group MLS Delivery
// Service ("biset-mls-ds"). HTTP is the only transport -- no DID/DIDComm
// identity for this service to configure at all any more; it never sends
// anything (fanout.ts was deleted) and never resolves anything (authorizer.ts
// verifies against the group-local id embedded in each request).
import { createConversationDsDeployment } from './deployment.ts'

const databasePath = Bun.env.CONVERSATION_DS_DATABASE_PATH
if (!databasePath) throw new Error('CONVERSATION_DS_DATABASE_PATH is required')

const deployment = createConversationDsDeployment({ databasePath })

const port = envInteger('PORT', 8792, 1, 65_535)
// Bun.serve's own idleTimeout defaults to 10s -- far too short for
// `GET /deliveries/stream` (http.ts's long-lived SSE connection, open for
// as long as a client stays subscribed to a group). Found live 2026-09-01:
// every real connection through Caddy died at 9.7-11.6s with "unexpected
// EOF", which the browser saw as a CORS failure (a Caddy-generated 502
// carries none of the app's own Access-Control-Allow-Origin), not a
// timeout -- confusing to debug from the client side alone. Raised to
// Bun's maximum (255s) as defense in depth alongside http.ts's own
// heartbeat comment (every 15s), which is what actually keeps a quiet
// group's connection from ever going idle in the first place.
Bun.serve({ port, fetch: deployment.fetch, idleTimeout: 255 })
console.info(`biset-mls-ds listening on :${port}`)

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => { deployment.close(); process.exit(0) })
}

function envInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = Bun.env[name]
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${name} must be an integer between ${min} and ${max}`)
  }
  return value
}
