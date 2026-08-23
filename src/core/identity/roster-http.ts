import { installRosterProjection, type DeviceControlSignatureVerifier } from './authorizers.ts'
import { decodeRosterInstallWire } from './roster-install.ts'
import { encodeAcceptedSelfGroupProjectionWire, type TrustedDeviceRoster } from './device-roster.ts'

const MAX_BODY_BYTES = 16 * 1024

/**
 * Narrow HTTP boundary for the roster: `POST /v1/roster/install` is the only
 * way a caller can move an `AcceptedSelfGroupProjectionV1` into core's
 * roster (`installRosterProjection`, authorizers.ts, enforces core's
 * DS-only trust model — `PLANMLSARCH.md` §4). `GET /v1/roster/:identityId`
 * reads the current projection back — unauthenticated, since it names only
 * public device ids and signing key ids (device-roster.ts's own note on
 * why) — for a producer to seed `buildAcceptedSelfGroupProjection`'s
 * `previous` argument before building the next one.
 */
export function createRosterInstallHttpHandler(
  roster: TrustedDeviceRoster,
  verifier: Pick<DeviceControlSignatureVerifier, 'verifyRosterInstall'>,
): (request: Request) => Promise<Response> {
  return async (request) => {
    try {
      const path = new URL(request.url).pathname

      if (request.method === 'GET' && path.startsWith('/v1/roster/') && path !== '/v1/roster/install') {
        const identityId = decodeURIComponent(path.slice('/v1/roster/'.length))
        const projection = identityId && (await roster.projection(identityId))
        if (!projection) return text(404, 'Not found')
        return json(200, encodeAcceptedSelfGroupProjectionWire(projection))
      }

      if (request.method !== 'POST') return text(405, 'Method not allowed')
      if (path !== '/v1/roster/install') return text(404, 'Not found')
      const install = decodeRosterInstallWire(await requestText(request))
      const outcome = await installRosterProjection(roster, verifier, install)
      if (outcome === 'rejected') return text(403, 'rejected')
      return json(outcome === 'installed' ? 201 : 200, JSON.stringify({ outcome }))
    } catch (error) {
      if (error instanceof TypeError || error instanceof RangeError) return text(400, error.message)
      return text(500, 'Internal server error')
    }
  }
}

async function requestText(request: Request): Promise<string> {
  const length = request.headers.get('content-length')
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) {
    throw new RangeError('roster install HTTP body is too large')
  }
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('roster install HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}
function text(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } })
}
