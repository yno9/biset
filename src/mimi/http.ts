/** Narrow HTTP boundary for MIMI provider endpoints implemented in Phase 0. */
import {
  authorizeKeyMaterial,
  authorizeUpdate,
  authorizeDeliveriesPull,
  authorizeDeliveriesWatch,
  keyMaterialResponse,
  type MimiSignatureVerifier,
} from './authorizer.ts'
import {
  decodeKeyMaterialRequestWire,
  decodeDeliveriesPullRequestWire,
  decodeDeliveriesWatchRequestWire,
  decodeUpdateRoomRequestWire,
  encodeKeyMaterialResponseWire,
  encodeDeliveriesWire,
  encodeDeliveriesWatchTokenWire,
  encodeMimiErrorWire,
  encodeUpdateRoomResponseWire,
  MimiWireError,
  deliveryEntryWireJson,
} from './wire.ts'
import { MimiStoreCapacityError, MimiStoreStateError, type SqliteMimiStore } from './store.ts'
import type { MimiErrorResponse, UpdateRoomResponse } from './protocol-types.ts'
import type { MimiWatchTokenIssuer } from './watch-token.ts'

const MAX_BODY_BYTES = 1024 * 1024
const KEY_MATERIAL_PREFIX = '/keyMaterial/'
const UPDATE_PREFIX = '/update/'
const DELIVERY_PULL_PATH = '/v1/mimi/deliveries/pull'
const DELIVERY_WATCH_PATH = '/v1/mimi/deliveries/watch'
const DELIVERY_STREAM_PATH = '/v1/mimi/deliveries/stream'

function isMimiHttpPath(path: string): boolean {
  return path.startsWith(KEY_MATERIAL_PREFIX) || path.startsWith(UPDATE_PREFIX)
    || path === DELIVERY_PULL_PATH || path === DELIVERY_WATCH_PATH || path === DELIVERY_STREAM_PATH
}

/**
 * MIMI draft §5.2 / §5.3 provider-facing routes.  Biset's calls arrive from
 * local clients, so every body additionally uses the provider-internal
 * credential signature defined in authorizer.ts.
 */
export function createMimiHttpHandler(
  store: SqliteMimiStore,
  verifier: MimiSignatureVerifier,
  watchTokens: MimiWatchTokenIssuer,
): (request: Request) => Promise<Response> {
  return async request => {
    try {
      const path = new URL(request.url).pathname
      if (!isMimiHttpPath(path)) return error(404, 'not-found', 'Not found')
      if (path === DELIVERY_STREAM_PATH) {
        if (request.method !== 'GET') return error(405, 'bad-request', 'Method not allowed')
        return streamDeliveries(store, watchTokens, new URL(request.url))
      }
      if (request.method !== 'POST') return error(405, 'bad-request', 'Method not allowed')
      const body = await requestText(request)

      if (path.startsWith(KEY_MATERIAL_PREFIX)) {
        const targetUser = pathParameter(path, KEY_MATERIAL_PREFIX, 'target user')
        const value = decodeKeyMaterialRequestWire(body)
        if (value.targetUser !== targetUser) return error(400, 'bad-request', 'target user path does not match request body')
        if (!(await authorizeKeyMaterial(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room membership was rejected')
        return json(200, encodeKeyMaterialResponseWire(keyMaterialResponse(value.targetUser, store.takeKeyPackages(value.targetUser, value.requiredCapabilities))))
      }

      if (path.startsWith(UPDATE_PREFIX)) {
        const roomId = pathParameter(path, UPDATE_PREFIX, 'room ID')
        const value = decodeUpdateRoomRequestWire(body)
        if (value.roomId !== roomId) return error(400, 'bad-request', 'room ID path does not match request body')
        if (!(await authorizeUpdate(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        const result = store.submitUpdate(value)
        if (result.ok) return json(200, encodeUpdateRoomResponseWire({ status: 'success', acceptedTimestamp: value.submittedAt }))
        return updateError(result.reason, result.message, result.currentEpoch)
      }

      if (path === DELIVERY_PULL_PATH) {
        const value = decodeDeliveriesPullRequestWire(body)
        if (!(await authorizeDeliveriesPull(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        return json(200, encodeDeliveriesWire(store.deliveriesSince(value.roomId, value.requester.user, value.afterSeq) ?? []))
      }

      if (path === DELIVERY_WATCH_PATH) {
        const value = decodeDeliveriesWatchRequestWire(body)
        if (!(await authorizeDeliveriesWatch(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        return json(200, encodeDeliveriesWatchTokenWire(watchTokens.issue(value.roomId, value.requester.user)))
      }

      return error(404, 'not-found', 'Not found')
    } catch (cause) {
      if (cause instanceof MimiWireError || cause instanceof MimiStoreCapacityError || cause instanceof MimiStoreStateError || cause instanceof RangeError || cause instanceof TypeError) {
        return error(400, 'bad-request', cause.message)
      }
      return error(500, 'internal-error', 'Internal server error')
    }
  }
}

/**
 * Authenticated SSE tail.  Backlog and subscribe happen in the same
 * synchronous `start()` call, so no delivery is lost between them.  The first
 * comment is deliberately sent even for an empty backlog: it flushes headers
 * immediately instead of making EventSource wait for the heartbeat.
 */
function streamDeliveries(store: SqliteMimiStore, watchTokens: MimiWatchTokenIssuer, url: URL): Response {
  const token = url.searchParams.get('token')
  const afterSeqText = url.searchParams.get('afterSeq')
  if (!token || afterSeqText === null || !/^[0-9]+$/.test(afterSeqText)) return error(400, 'bad-request', 'token and afterSeq query parameters are required')
  const afterSeq = Number(afterSeqText)
  if (!Number.isSafeInteger(afterSeq)) return error(400, 'bad-request', 'afterSeq is too large')
  const record = watchTokens.resolve(token)
  if (!record) return error(403, 'unauthorized', 'invalid or expired watch token')

  let cursor = afterSeq
  let unsubscribe: (() => void) | undefined
  let heartbeat: ReturnType<typeof setInterval> | undefined
  const encoder = new TextEncoder()
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(': connected\n\n'))
      const send = (entry: Parameters<typeof deliveryEntryWireJson>[0]) => {
        const json = deliveryEntryWireJson(entry)
        controller.enqueue(encoder.encode(`id: ${json.seq}\ndata: ${JSON.stringify(json)}\n\n`))
        cursor = entry.seq
      }
      for (const entry of store.deliveriesSince(record.roomId, record.requester, afterSeq) ?? []) send(entry)
      unsubscribe = store.subscribe(record.roomId, entries => {
        for (const entry of entries) if (entry.seq > cursor) send(entry)
      })
      heartbeat = setInterval(() => controller.enqueue(encoder.encode(': ping\n\n')), 15_000)
    },
    cancel() {
      unsubscribe?.()
      if (heartbeat !== undefined) clearInterval(heartbeat)
    },
  })
  return new Response(stream, { headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' } })
}

function updateError(reason: 'wrongEpoch' | 'notAllowed' | 'invalidProposal' | 'roomExists', message: string, currentEpoch?: string): Response {
  const response: UpdateRoomResponse = reason === 'wrongEpoch'
    ? { status: 'wrongEpoch', currentEpoch, errorDescription: message }
    : reason === 'invalidProposal'
      ? { status: 'invalidProposal', errorDescription: message }
      : { status: 'notAllowed', errorDescription: message }
  const status = reason === 'wrongEpoch' || reason === 'roomExists' ? 409 : reason === 'invalidProposal' ? 400 : 403
  return json(status, encodeUpdateRoomResponseWire(response))
}

function pathParameter(path: string, prefix: string, name: string): string {
  const encoded = path.slice(prefix.length)
  if (!encoded || encoded.includes('/')) throw new MimiWireError(`${name} path parameter is required and must be percent encoded`)
  try {
    const value = decodeURIComponent(encoded)
    if (!value) throw new Error()
    return value
  } catch { throw new MimiWireError(`${name} path parameter is not valid percent encoding`) }
}

async function requestText(request: Request): Promise<string> {
  const contentType = request.headers.get('content-type')
  if (contentType?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') throw new TypeError('Content-Type must be application/json')
  const length = request.headers.get('content-length')
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('MIMI HTTP body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('MIMI HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}

function error(status: number, errorCode: MimiErrorResponse['error'], message: string): Response {
  return json(status, encodeMimiErrorWire({ error: errorCode, message }))
}
