import { ProtocolValidationError } from '../../protocol/validate.ts'
import {
  decodeRestoreCancelWire,
  decodeRestoreControlPullWire,
  decodeRestoreOfferWire,
  decodeRestoreRequestWire,
  encodeRestoreOffersWire,
  encodeRestoreRequestsWire,
} from '../../protocol/restore-control-wire.ts'
import type { RestoreControlStore } from './restore-control-store.ts'

const MAX_BODY_BYTES = 64 * 1024

/** Narrow HTTP surface for restore signalling only; never for vault transfer. */
export function createRestoreControlHttpHandler(store: RestoreControlStore): (request: Request) => Promise<Response> {
  return async request => {
    try {
      if (request.method !== 'POST') return text(405, 'Method not allowed')
      const body = await requestText(request)
      const path = new URL(request.url).pathname
      if (path === '/v1/restore/request') {
        await store.request(decodeRestoreRequestWire(body))
        return json(202, '{}')
      }
      if (path === '/v1/restore/requests/pull') return json(200, encodeRestoreRequestsWire(await store.pullRequests(decodeRestoreControlPullWire(body))))
      if (path === '/v1/restore/offer') {
        await store.offer(decodeRestoreOfferWire(body))
        return json(202, '{}')
      }
      if (path === '/v1/restore/offers/pull') return json(200, encodeRestoreOffersWire(await store.pullOffers(decodeRestoreControlPullWire(body))))
      if (path === '/v1/restore/cancel') {
        await store.cancel(decodeRestoreCancelWire(body))
        return json(202, '{}')
      }
      return text(404, 'Not found')
    } catch (error) {
      if (error instanceof ProtocolValidationError || error instanceof TypeError || error instanceof RangeError) return text(400, error.message)
      return text(500, 'Internal server error')
    }
  }
}

async function requestText(request: Request): Promise<string> {
  const length = request.headers.get('content-length')
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('restore control HTTP body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('restore control HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response { return new Response(body, { status, headers: { 'content-type': 'application/json' } }) }
function text(status: number, body: string): Response { return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } }) }
