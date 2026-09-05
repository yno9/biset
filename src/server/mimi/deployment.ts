/** Composition root for one standalone biset-mimi provider deployment. */
import { Ed25519MimiSignatureVerifier } from '../../shared/mimi/authorizer.ts'
import { createMimiHttpHandler, type MimiFederationOptions } from './http.ts'
import { SqliteMimiStore } from './store.ts'
import { MimiWatchTokenIssuer } from './watch-token.ts'
import type { MimiDeploymentMode } from '../../shared/mimi/protocol-types.ts'

const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
}

export interface MimiDeploymentOptions {
  databasePath: string
  /** Each mode must use its own process and SQLite file. */
  mode: MimiDeploymentMode
  /** Public HTTPS origin advertised by the MIMI well-known directory. */
  publicBaseUrl?: string
  federation?: MimiFederationOptions
  /**
   * Enables `POST /groupInfo/{roomId}` (draft §5.6 external join) instead of
   * the default explicit refusal. Only turn this on for a deployment
   * dedicated to Self Group traffic (one user's own devices) -- a GroupInfo
   * ratchet tree discloses every member's real credential to whoever fetches
   * it, which is fine when the only possible members are the room's own
   * owner, and a serious leak for a third-party room (protocol-types.ts's
   * GroupInfoRequest doc comment). Defaults to false.
   */
  allowExternalJoin?: boolean
}

export interface MimiServerOptions extends MimiDeploymentOptions { port: number }

/**
 * Builds the provider's fetch handler without opening a listener.  Keeping
 * this separate makes the HTTP layer testable while the entrypoint owns
 * process signals and listening configuration.
 */
export function createMimiDeployment(options: MimiDeploymentOptions) {
  const store = SqliteMimiStore.open(options.databasePath, options.mode)
  const verifier = new Ed25519MimiSignatureVerifier()
  const watchTokens = new MimiWatchTokenIssuer()
  const inner = createMimiHttpHandler(store, verifier, watchTokens, options.mode, options.publicBaseUrl, options.federation, options.allowExternalJoin ?? false)
  return {
    mode: options.mode,
    store,
    async fetch(request: Request): Promise<Response> {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })
      const response = await inner(request)
      const headers = new Headers(response.headers)
      for (const [key, value] of Object.entries(CORS)) headers.set(key, value)
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
    },
    close(): void { store.close() },
  }
}

/** Starts a MIMI provider with the SSE-safe Bun idle timeout. */
export function serveMimiDeployment(options: MimiServerOptions) {
  const deployment = createMimiDeployment(options)
  // Bun's default idle timeout is roughly 10 seconds, which silently closes a
  // quiet SSE connection before its 15-second heartbeat.  255 is Bun's
  // maximum and provides defense in depth alongside http.ts's heartbeat.
  const server = Bun.serve({ port: options.port, fetch: deployment.fetch, idleTimeout: 255 })
  return { ...deployment, server }
}
