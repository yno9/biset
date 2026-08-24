import { ProtocolValidationError } from '../../protocol/validate.ts'
import { decodeMailSubmissionRequestWire, encodeMailSubmissionResultWire } from '../../protocol/mail-submission-wire.ts'
import type { CoreMailSubmissionAdapter } from '../adapters/mail-submission-adapter.ts'

const MAX_BODY_BYTES = 25 * 1024 * 1024

/**
 * Endpoint-facing outbound mail submission. Accepts only a signed
 * MailSubmissionRequestV1 -- device-control authorization happens inside
 * CoreMailSubmissionAdapter.submit(), not here.
 */
export function createMailSubmissionHttpHandler(adapter: CoreMailSubmissionAdapter): (request: Request) => Promise<Response> {
  return async (request) => {
    try {
      if (request.method !== 'POST') return text(405, 'Method not allowed')
      const body = await requestText(request)
      const path = new URL(request.url).pathname
      if (path === '/v1/mail/submit') return json(200, encodeMailSubmissionResultWire(await adapter.submit(decodeMailSubmissionRequestWire(body))))
      return text(404, 'Not found')
    } catch (error) {
      if (error instanceof ProtocolValidationError || error instanceof TypeError || error instanceof RangeError) return text(400, error.message)
      if (error instanceof Error && error.message === 'mail submission is not authorised') return text(403, error.message)
      return text(500, 'Internal server error')
    }
  }
}

async function requestText(request: Request): Promise<string> {
  const length = request.headers.get('content-length')
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('mail submission HTTP body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('mail submission HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}
function text(status: number, body: string): Response { return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } }) }
