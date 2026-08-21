import { ProtocolValidationError } from '../../protocol/validate.ts'
import { decodeIngressAckWire, decodeIngressPullWire, encodeIngressPullResultWire } from '../../protocol/ingress-wire.ts'
import type { IngressStore } from './ingress-store.ts'

const MAX_BODY_BYTES = 64 * 1024

/**
 * Endpoint-facing bounded ingress receive API. It accepts only signed pull and
 * ACK controls; an external transport adapter cannot offer arbitrary bodies
 * through this public HTTP surface.
 */
export function createIngressHttpHandler(store: IngressStore): (request: Request) => Promise<Response> {
  return async (request) => {
    try {
      if (request.method !== 'POST') return text(405, 'Method not allowed')
      const body = await requestText(request)
      const path = new URL(request.url).pathname
      if (path === '/v1/ingress/pull') return json(200, encodeIngressPullResultWire(await store.pull(decodeIngressPullWire(body))))
      if (path === '/v1/ingress/ack') {
        await store.acknowledge(decodeIngressAckWire(body))
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
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('ingress HTTP body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('ingress HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}
function text(status: number, body: string): Response { return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } }) }
