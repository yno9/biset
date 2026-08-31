// Production entrypoint for the standalone Conversation Group MLS Delivery
// Service ("biset-mls-ds"). HTTP transport (Phase 2a) serves immediately;
// the DIDComm transport (Phase 2b, `deployment.handleDidCommMessage`) is
// exposed but not yet wired to an inbound source here -- Phase 3 connects
// it to a mediator pickup loop or direct ingress.
import { hexToBytes } from '../protocol/canonical.ts'
import { createConversationDsDeployment } from './deployment.ts'

const databasePath = Bun.env.CONVERSATION_DS_DATABASE_PATH
if (!databasePath) throw new Error('CONVERSATION_DS_DATABASE_PATH is required')

const self = Bun.env.CONVERSATION_DS_DID
if (!self) throw new Error('CONVERSATION_DS_DID is required')

const fromKid = Bun.env.CONVERSATION_DS_DIDCOMM_KID
if (!fromKid) throw new Error('CONVERSATION_DS_DIDCOMM_KID is required')

const x25519PrivateKeyHex = Bun.env.CONVERSATION_DS_X25519_PRIVATE_KEY
if (!x25519PrivateKeyHex) throw new Error('CONVERSATION_DS_X25519_PRIVATE_KEY is required')

const deployment = createConversationDsDeployment({
  databasePath,
  self,
  sendOpts: { fromKid, x25519PrivateKey: hexToBytes(x25519PrivateKeyHex) },
})

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
