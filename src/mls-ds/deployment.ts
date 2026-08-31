// Composes the Conversation Group DS engine (store.ts) with its one
// transport (the narrow HTTP handler, http.ts) -- no DIDComm binding any
// more (conversation-mls-ds.ts's header explains why it was deleted, not
// just left unwired).
import { Ed25519ConversationDsSignatureVerifier } from './authorizer.ts'
import { createConversationDeliveryHttpHandler } from './http.ts'
import { SqliteConversationDeliveryService } from './store.ts'

export interface ConversationDsDeploymentOptions {
  databasePath: string
}

export function createConversationDsDeployment(options: ConversationDsDeploymentOptions) {
  const ds = SqliteConversationDeliveryService.open(options.databasePath)
  const verifier = new Ed25519ConversationDsSignatureVerifier()
  return {
    ds,
    fetch: createConversationDeliveryHttpHandler(ds, verifier),
    close(): void { ds.close() },
  }
}
