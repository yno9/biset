import { decodeVaultCoordinatorAck, decodeVaultCoordinatorAppend, decodeVaultCoordinatorCheckpointPull, decodeVaultCoordinatorCheckpointPut, decodeVaultCoordinatorPull, encodeVaultCoordinatorCheckpoint, encodeVaultCoordinatorOwnedVaults, encodeVaultCoordinatorPullResult } from '../protocol/coordinator.ts'
import { decodeVaultGroupView } from '../protocol/vault-group-view.ts'
import {
  decodeVaultMlsKeyPackage,
  decodeVaultMlsMemberRequest,
  decodeVaultMlsTransition,
  encodeVaultMlsKeyPackageList,
  encodeVaultMlsTransitionItems,
  encodeVaultMlsWelcomeDelivery,
  decodeVaultMlsInvitationRedeem,
  encodeVaultMlsInvitation,
  encodeVaultMlsInvitationRedemption,
} from '../protocol/vault-mls-ds.ts'
import { authorizeBearer, VaultAuthenticationError, VaultAuthenticationUnavailableError, VaultAuthorizationError, type VaultAccessTokenVerifier } from './auth.ts'
import { SqliteVaultCoordinatorStore, VaultCoordinatorConflictError, VaultCoordinatorNotFoundError, VaultCoordinatorStoreError } from './store.ts'
import { decodeVaultStreamAppend, decodeVaultStreamCheckpointPull, decodeVaultStreamCheckpointPut, decodeVaultStreamPull, encodeVaultStream, encodeVaultStreamCheckpoint, encodeVaultStreamPullResult } from '../protocol/coordinator-stream.ts'

const MAX_BODY_BYTES = 40 * 1024 * 1024
const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type',
  'access-control-max-age': '86400',
}

export interface VaultCoordinatorApplicationOptions {
  store: SqliteVaultCoordinatorStore
  accessTokens: VaultAccessTokenVerifier
}

export function createVaultCoordinatorFetchHandler(options: VaultCoordinatorApplicationOptions): (request: Request) => Promise<Response> {
  return async (request): Promise<Response> => {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS })
    const path = new URL(request.url).pathname
    if (path === '/healthz' && request.method === 'GET') return json(200, { ok: true, service: 'biset-coordinator' })
    if (request.method !== 'POST') return text(405, 'Method not allowed')
    try {
      if (path === '/v2/vaults/default') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.create')
        const input = JSON.parse(await requestText(request)) as unknown
        if (input === null || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 1 || (input as Record<string, unknown>).version !== 2) throw new TypeError('default Vault stream request is invalid')
        return rawJson(200, encodeVaultStream(options.store.defaultStream(principal.subject)))
      }
      if (path === '/v2/entries/append') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.append')
        const item = options.store.appendStream(decodeVaultStreamAppend(await requestText(request)), principal.subject)
        return json(202, { seq: item.seq })
      }
      if (path === '/v2/entries/pull') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.pull')
        const input = decodeVaultStreamPull(await requestText(request))
        return rawJson(200, encodeVaultStreamPullResult(options.store.pullStream(input.vaultId, input.after, principal.subject)))
      }
      if (path === '/v2/checkpoints/put') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.append')
        options.store.putStreamCheckpoint(decodeVaultStreamCheckpointPut(await requestText(request)), principal.subject)
        return json(202, {})
      }
      if (path === '/v2/checkpoints/pull') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.pull')
        const input = decodeVaultStreamCheckpointPull(await requestText(request))
        return rawJson(200, encodeVaultStreamCheckpoint(options.store.pullStreamCheckpoint(input.vaultId, principal.subject)))
      }
      if (path === '/v1/vaults') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.create')
        const groupViewHash = options.store.create(decodeVaultGroupView(await requestText(request)), principal.subject)
        return json(201, { groupViewHash })
      }
      if (path === '/v1/vaults/owned') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.pull')
        const input = JSON.parse(await requestText(request)) as unknown
        if (input === null || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 1 || (input as Record<string, unknown>).version !== 1) throw new TypeError('owned Vault request is invalid')
        return rawJson(200, encodeVaultCoordinatorOwnedVaults(options.store.ownedVaults(principal.subject)))
      }
      // Group updates must bind the routing view to the exact MLS commit and
      // Welcome set. The former view-only endpoint is intentionally gone.
      if (path === '/v1/group/install') return text(410, 'use /v1/mls/transitions/install')
      if (path === '/v1/mls/key-packages/publish') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.group.install')
        options.store.publishKeyPackage(decodeVaultMlsKeyPackage(await requestText(request)), principal.subject)
        return json(202, {})
      }
      if (path === '/v1/mls/key-packages/pull') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.group.install')
        return rawJson(200, encodeVaultMlsKeyPackageList(options.store.pullKeyPackages(decodeVaultMlsMemberRequest(await requestText(request)), principal.subject)))
      }
      if (path === '/v1/mls/transitions/install') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.group.install')
        const groupViewHash = options.store.installMlsTransition(decodeVaultMlsTransition(await requestText(request)), principal.subject)
        return json(200, { groupViewHash })
      }
      if (path === '/v1/mls/transitions/pull') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.group.install')
        return rawJson(200, encodeVaultMlsTransitionItems(options.store.pullMlsTransitions(decodeVaultMlsMemberRequest(await requestText(request)), principal.subject)))
      }
      if (path === '/v1/mls/welcomes/pull') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.group.install')
        return rawJson(200, encodeVaultMlsWelcomeDelivery(options.store.pullMlsWelcome(decodeVaultMlsMemberRequest(await requestText(request)), principal.subject)))
      }
      if (path === '/v1/mls/invitations/create') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.group.install')
        return rawJson(201, encodeVaultMlsInvitation(options.store.createMlsInvitation(decodeVaultMlsMemberRequest(await requestText(request)), principal.subject)))
      }
      if (path === '/v1/mls/invitations/redeem') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.group.install')
        return rawJson(200, encodeVaultMlsInvitationRedemption(options.store.redeemMlsInvitation(decodeVaultMlsInvitationRedeem(await requestText(request)), principal.subject)))
      }
      if (path === '/v1/deliveries/append') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.append')
        const item = options.store.append(decodeVaultCoordinatorAppend(await requestText(request)), principal.subject)
        return json(202, { seq: item.seq })
      }
      if (path === '/v1/deliveries/pull') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.pull')
        return rawJson(200, encodeVaultCoordinatorPullResult(options.store.pull(decodeVaultCoordinatorPull(await requestText(request)), principal.subject)))
      }
      if (path === '/v1/deliveries/ack') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.ack')
        options.store.acknowledge(decodeVaultCoordinatorAck(await requestText(request)), principal.subject)
        return json(202, {})
      }
      if (path === '/v1/checkpoints/put') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.append')
        options.store.putCheckpoint(decodeVaultCoordinatorCheckpointPut(await requestText(request)), principal.subject)
        return json(202, {})
      }
      if (path === '/v1/checkpoints/pull') {
        const principal = await authorizeBearer(request, options.accessTokens, 'vault.pull')
        const input = decodeVaultCoordinatorCheckpointPull(await requestText(request))
        return rawJson(200, encodeVaultCoordinatorCheckpoint(options.store.pullCheckpoint(input.vaultId, principal.subject)))
      }
      return text(404, 'Not found')
    } catch (error) {
      if (error instanceof VaultAuthenticationError) return bearerError(401, 'invalid_token', error.message)
      if (error instanceof VaultAuthenticationUnavailableError) return text(503, error.message)
      if (error instanceof VaultAuthorizationError) return bearerError(403, 'insufficient_scope', error.message)
      if (error instanceof VaultCoordinatorNotFoundError) return text(404, error.message)
      if (error instanceof VaultCoordinatorConflictError) return text(409, error.message)
      if (error instanceof VaultCoordinatorStoreError || error instanceof TypeError || error instanceof RangeError) return text(400, error.message)
      return text(500, 'Internal server error')
    }
  }
}

async function requestText(request: Request): Promise<string> {
  if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') throw new TypeError('Content-Type must be application/json')
  const length = request.headers.get('content-length')
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('Vault Coordinator body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('Vault Coordinator body is too large')
  return new TextDecoder().decode(bytes)
}

function bearerError(status: number, error: string, description: string): Response {
  return new Response(description, { status, headers: { ...CORS_HEADERS, 'content-type': 'text/plain; charset=utf-8', 'www-authenticate': `Bearer error="${error}"` } })
}
function json(status: number, value: unknown): Response { return rawJson(status, JSON.stringify(value)) }
function rawJson(status: number, body: string): Response { return new Response(body, { status, headers: { ...CORS_HEADERS, 'content-type': 'application/json' } }) }
function text(status: number, body: string): Response { return new Response(body, { status, headers: { ...CORS_HEADERS, 'content-type': 'text/plain; charset=utf-8' } }) }
