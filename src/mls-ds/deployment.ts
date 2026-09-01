// Composes the Conversation Group DS engine (store.ts) with its one
// transport (the narrow HTTP handler, http.ts) -- no DIDComm binding any
// more (conversation-mls-ds.ts's header explains why it was deleted, not
// just left unwired).
import { Ed25519ConversationDsSignatureVerifier } from './authorizer.ts'
import { createConversationDeliveryHttpHandler } from './http.ts'
import { SqliteConversationDeliveryService } from './store.ts'
import { ConversationWatchTokenIssuer } from './watch-token.ts'

// A browser client and this DS are never same-origin by design (the whole
// point of a Conversation Group DS is being a standalone service any
// biset-compatible web app can point at, not something bundled behind the
// same domain) -- every POST here carries `content-type: application/json`,
// which is not a CORS-simple header, so the browser preflights it with an
// OPTIONS request first. Without an answer to that (and without
// Access-Control-Allow-Origin on the real response), the request never even
// leaves the browser. Same fix, same CORS set, as core/app.ts's own
// createBisetCoreFetchHandler wrapper -- that file's own comment records
// this exact failure mode being found live once already ("none of them
// answered with Access-Control-Allow-Origin, so the actual request never
// even went out"), for the identical "narrow JSON API a browser calls
// cross-origin" shape this deployment is too. Wrapped here (the composition
// root), not inside http.ts itself, so http.ts's own tests -- which call
// createConversationDeliveryHttpHandler directly -- stay CORS-agnostic.
const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
}

export interface ConversationDsDeploymentOptions {
  databasePath: string
}

export function createConversationDsDeployment(options: ConversationDsDeploymentOptions) {
  const ds = SqliteConversationDeliveryService.open(options.databasePath)
  const verifier = new Ed25519ConversationDsSignatureVerifier()
  const watchTokens = new ConversationWatchTokenIssuer()
  const inner = createConversationDeliveryHttpHandler(ds, verifier, watchTokens)
  return {
    ds,
    async fetch(request: Request): Promise<Response> {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })
      const response = await inner(request)
      const headers = new Headers(response.headers)
      for (const [key, value] of Object.entries(CORS)) headers.set(key, value)
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
    },
    close(): void { ds.close() },
  }
}
