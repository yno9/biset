/** Narrow HTTP boundary for MIMI provider endpoints implemented in Phase 0. */
import {
  authorizeKeyMaterial,
  authorizeUpdate,
  keyMaterialResponse,
  type MimiSignatureVerifier,
} from './authorizer.ts'
import {
  decodeKeyMaterialRequestWire,
  decodeUpdateRoomRequestWire,
  encodeKeyMaterialResponseWire,
  encodeMimiErrorWire,
  encodeUpdateRoomResponseWire,
  MimiWireError,
} from './wire.ts'
import { MimiStoreCapacityError, MimiStoreStateError, type SqliteMimiStore } from './store.ts'
import type { MimiErrorResponse, MimiRoomId, MimiUserUri, UpdateRoomResponse } from './protocol-types.ts'

const MAX_BODY_BYTES = 1024 * 1024
const KEY_MATERIAL_PREFIX = '/keyMaterial/'
const UPDATE_PREFIX = '/update/'

export function isMimiHttpPath(path: string): boolean {
  return path.startsWith(KEY_MATERIAL_PREFIX) || path.startsWith(UPDATE_PREFIX)
}

/**
 * MIMI draft §5.2 / §5.3 provider-facing routes.  Biset's calls arrive from
 * local clients, so every body additionally uses the provider-internal
 * credential signature defined in authorizer.ts.
 */
export function createMimiHttpHandler(
  store: SqliteMimiStore,
  verifier: MimiSignatureVerifier,
): (request: Request) => Promise<Response> {
  return async request => {
    try {
      const path = new URL(request.url).pathname
      if (!isMimiHttpPath(path)) return error(404, 'not-found', 'Not found')
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

      return error(404, 'not-found', 'Not found')
    } catch (cause) {
      if (cause instanceof MimiWireError || cause instanceof MimiStoreCapacityError || cause instanceof MimiStoreStateError || cause instanceof RangeError || cause instanceof TypeError) {
        return error(400, 'bad-request', cause.message)
      }
      return error(500, 'internal-error', 'Internal server error')
    }
  }
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
