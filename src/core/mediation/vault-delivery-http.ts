import type { VaultDeliveryStore } from './vault-delivery-store.ts'
import { ProtocolValidationError } from '../../protocol/validate.ts'
import {
  decodeVaultDeliveryAckWire,
  decodeVaultDeliveryAppendWire,
  decodeVaultDeliveryPullWire,
  encodeDeliveryPullResultWire,
} from '../../protocol/vault-delivery-wire.ts'

const MAX_BODY_BYTES = 40 * 1024 * 1024

/**
 * HTTP adapter for bounded vault delivery only. It intentionally exposes no
 * Email/get, search, archive export, or generic blob endpoint.
 */
export function createVaultDeliveryHttpHandler(store: VaultDeliveryStore): (request: Request) => Promise<Response> {
  return async (request) => {
    try {
      if (request.method !== 'POST') return text(405, 'Method not allowed')
      const body = await requestText(request)
      const path = new URL(request.url).pathname
      if (path === '/v1/vault-delivery/append') {
        await store.append(decodeVaultDeliveryAppendWire(body))
        return json(202, '{}')
      }
      if (path === '/v1/vault-delivery/pull') return json(200, encodeDeliveryPullResultWire(await store.pull(decodeVaultDeliveryPullWire(body))))
      if (path === '/v1/vault-delivery/ack') {
        await store.acknowledge(decodeVaultDeliveryAckWire(body))
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
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('vault delivery HTTP body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('vault delivery HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}
function text(status: number, body: string): Response { return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } }) }
