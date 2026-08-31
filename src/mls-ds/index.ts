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
Bun.serve({ port, fetch: deployment.fetch })
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
