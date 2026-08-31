// Narrow HTTP boundary for the Conversation Group DS (mls-ds-1.0.md), mirroring
// coordinator/mls-delivery-http.ts's transport-only design. The ONLY
// transport now (a DIDComm envelope binding existed briefly but was
// deleted, not just left unwired -- conversation-mls-ds.ts's header
// explains why: push delivery required resolving a real DID to route to,
// which is exactly the kind of leak this DS's identity-blind redesign
// closes. Every control-message need (including catching up on new
// messages) goes through this narrow request/response API.
import {
  clearConversationPendingRemovals,
  createConversationGroup,
  dropConversationKeyPackages,
  publishConversationKeyPackages,
  pullConversationDeliveries,
  pullConversationKeyPackageCount,
  submitConversationCommit,
  submitConversationMessage,
  submitConversationSelfRemove,
  takeConversationKeyPackage,
  type ConversationDsSignatureVerifier,
} from './authorizer.ts'
import {
  ConversationDsWireError,
  decodeConversationCommitSubmitWire,
  decodeConversationDeliveriesPullWire,
  decodeConversationGroupCreateWire,
  decodeConversationKeyPackageCountPullWire,
  decodeConversationKeyPackageDropWire,
  decodeConversationKeyPackagePublishWire,
  decodeConversationKeyPackageTakeWire,
  decodeConversationMessageSubmitWire,
  decodeConversationPendingRemovalsClearWire,
  decodeConversationSelfRemoveSubmitWire,
  encodeConversationDeliveriesWire,
  encodeConversationKeyPackageTakenWire,
} from '../protocol/conversation-mls-ds-wire.ts'
import { ConversationDsCapacityError, type SqliteConversationDeliveryService } from './store.ts'

const MAX_BODY_BYTES = 1024 * 1024
const CONVERSATION_MLS_PATHS = new Set([
  '/v1/conversation-mls/group/create', '/v1/conversation-mls/commit/submit',
  '/v1/conversation-mls/keypackage/publish', '/v1/conversation-mls/keypackage/take',
  '/v1/conversation-mls/self-remove/submit', '/v1/conversation-mls/pending-removals/clear', '/v1/conversation-mls/deliveries/pull',
  '/v1/conversation-mls/keypackage/drop', '/v1/conversation-mls/keypackage/count',
  '/v1/conversation-mls/message/submit',
])

export function isConversationMlsDeliveryPath(path: string): boolean { return CONVERSATION_MLS_PATHS.has(path) }

/**
 * Narrow HTTP boundary for the Conversation Group DS (RFC 9750 §5, biset's
 * own docs/protocols/mls-ds-1.0.md semantics carried here over HTTP instead
 * of DIDComm for now). Every route requires the sender's own signature
 * (mls-ds/authorizer.ts); this handler is transport only.
 */
export function createConversationDeliveryHttpHandler(
  ds: SqliteConversationDeliveryService,
  verifier: ConversationDsSignatureVerifier,
): (request: Request) => Promise<Response> {
  return async (request) => {
    try {
      const path = new URL(request.url).pathname
      if (!isConversationMlsDeliveryPath(path)) return text(404, 'Not found')
      if (request.method !== 'POST') return text(405, 'Method not allowed')
      const body = await requestText(request)

      if (path === '/v1/conversation-mls/group/create') {
        const outcome = await createConversationGroup(ds, verifier, decodeConversationGroupCreateWire(body))
        if (!outcome.ok) return text(403, 'rejected')
        return json(201, JSON.stringify({ roster: outcome.roster }))
      }

      if (path === '/v1/conversation-mls/commit/submit') {
        return commitResponse(await submitConversationCommit(ds, verifier, decodeConversationCommitSubmitWire(body)))
      }

      if (path === '/v1/conversation-mls/keypackage/publish') {
        const count = await publishConversationKeyPackages(ds, verifier, decodeConversationKeyPackagePublishWire(body))
        if (count === undefined) return text(403, 'rejected')
        return json(200, JSON.stringify({ count }))
      }

      if (path === '/v1/conversation-mls/keypackage/take') {
        const taken = await takeConversationKeyPackage(ds, verifier, decodeConversationKeyPackageTakeWire(body))
        return json(200, encodeConversationKeyPackageTakenWire(taken))
      }

      if (path === '/v1/conversation-mls/self-remove/submit') {
        return commitResponse(await submitConversationSelfRemove(ds, verifier, decodeConversationSelfRemoveSubmitWire(body)))
      }

      if (path === '/v1/conversation-mls/pending-removals/clear') {
        const ok = await clearConversationPendingRemovals(ds, verifier, decodeConversationPendingRemovalsClearWire(body))
        if (!ok) return text(403, 'rejected')
        return json(200, '{}')
      }

      if (path === '/v1/conversation-mls/deliveries/pull') {
        const entries = await pullConversationDeliveries(ds, verifier, decodeConversationDeliveriesPullWire(body))
        if (entries === undefined) return text(403, 'rejected')
        return json(200, encodeConversationDeliveriesWire(entries))
      }

      if (path === '/v1/conversation-mls/keypackage/drop') {
        const ok = await dropConversationKeyPackages(ds, verifier, decodeConversationKeyPackageDropWire(body))
        if (!ok) return text(403, 'rejected')
        return json(200, '{}')
      }

      if (path === '/v1/conversation-mls/keypackage/count') {
        const count = await pullConversationKeyPackageCount(ds, verifier, decodeConversationKeyPackageCountPullWire(body))
        if (count === undefined) return text(403, 'rejected')
        return json(200, JSON.stringify({ count }))
      }

      if (path === '/v1/conversation-mls/message/submit') {
        return commitResponse(await submitConversationMessage(ds, verifier, decodeConversationMessageSubmitWire(body)))
      }

      return text(404, 'Not found')
    } catch (error) {
      if (error instanceof ConversationDsWireError || error instanceof ConversationDsCapacityError || error instanceof RangeError || error instanceof TypeError) return text(400, error.message)
      return text(500, 'Internal server error')
    }
  }
}

function commitResponse(result: { ok: true; roster: string[] } | { ok: false; reason: string; epoch: string }): Response {
  if (result.ok) return json(201, JSON.stringify({ roster: result.roster }))
  return json(result.reason === 'unauthorized' ? 403 : 409, JSON.stringify({ reason: result.reason, epoch: result.epoch }))
}

async function requestText(request: Request): Promise<string> {
  const contentType = request.headers.get('content-type')
  if (contentType?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') throw new TypeError('Content-Type must be application/json')
  const length = request.headers.get('content-length')
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('Conversation DS HTTP body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('Conversation DS HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}
function text(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } })
}
