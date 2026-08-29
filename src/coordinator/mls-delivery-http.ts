import {
  clearMlsPendingRemovals,
  createMlsGroup,
  dropMlsKeyPackages,
  publishMlsKeyPackages,
  pullMlsDeliveries,
  pullMlsGroupInfo,
  pullMlsGroupsFor,
  pullMlsKeyPackageCount,
  submitMlsCommit,
  submitMlsExternalCommit,
  submitMlsSelfRemove,
  takeMlsKeyPackages,
  type MlsDsSignatureVerifier,
} from './mls-delivery-authorizer.ts'
import {
  decodeMlsCommitSubmissionWire,
  decodeMlsDeliveriesPullWire,
  decodeMlsExternalCommitSubmissionWire,
  decodeMlsGroupCreationWire,
  decodeMlsGroupInfoPullWire,
  decodeMlsGroupsForPullWire,
  decodeMlsKeyPackageCountPullWire,
  decodeMlsKeyPackageDropWire,
  decodeMlsKeyPackagePublishWire,
  decodeMlsKeyPackageTakeWire,
  decodeMlsPendingRemovalsClearWire,
  decodeMlsSelfRemoveSubmissionWire,
  encodeMlsDeliveriesWire,
  encodeMlsGroupInfoAnswerWire,
  encodeMlsGroupsForWire,
  encodeMlsKeyPackagesTakenWire,
  MlsDsWireError,
} from '../protocol/mls-ds-wire.ts'
import { MlsDsCapacityError, type SqliteMlsDeliveryService } from './mls-delivery-store.ts'

const MAX_BODY_BYTES = 1024 * 1024
const SELF_GROUP_MLS_PATHS = new Set([
  '/v1/mls/group/create', '/v1/mls/commit/submit', '/v1/mls/commit/external',
  '/v1/mls/group-info/pull', '/v1/mls/keypackage/publish', '/v1/mls/keypackage/take',
  '/v1/mls/self-remove/submit', '/v1/mls/pending-removals/clear', '/v1/mls/deliveries/pull',
  '/v1/mls/keypackage/drop', '/v1/mls/keypackage/count', '/v1/mls/groups-for',
])

export function isSelfGroupMlsDeliveryPath(path: string): boolean { return SELF_GROUP_MLS_PATHS.has(path) }

/**
 * Narrow HTTP boundary for the MLS self-group DS (RFC 9750 §5): group
 * creation, commit submission (ordinary and external), GroupInfo pull, and
 * the KeyPackage directory. Every route requires the sender's own signature
 * (mls-delivery-authorizer.ts); this handler is transport only.
 */
export function createMlsDeliveryHttpHandler(
  ds: SqliteMlsDeliveryService,
  verifier: MlsDsSignatureVerifier,
  isLiveDevice: (identityId: string, kid: string) => Promise<boolean>,
): (request: Request) => Promise<Response> {
  return async (request) => {
    try {
      const path = new URL(request.url).pathname
      if (!isSelfGroupMlsDeliveryPath(path)) return text(404, 'Not found')
      if (request.method !== 'POST') return text(405, 'Method not allowed')
      const body = await requestText(request)

      if (path === '/v1/mls/group/create') {
        const outcome = await createMlsGroup(ds, verifier, decodeMlsGroupCreationWire(body))
        if (!outcome.ok) return text(403, 'rejected')
        return json(201, JSON.stringify({ roster: outcome.roster }))
      }

      if (path === '/v1/mls/commit/submit') {
        const result = await submitMlsCommit(ds, verifier, decodeMlsCommitSubmissionWire(body))
        return commitResponse(result)
      }

      if (path === '/v1/mls/commit/external') {
        const result = await submitMlsExternalCommit(ds, verifier, decodeMlsExternalCommitSubmissionWire(body))
        return commitResponse(result)
      }

      if (path === '/v1/mls/group-info/pull') {
        const result = await pullMlsGroupInfo(ds, verifier, decodeMlsGroupInfoPullWire(body))
        if (!result.ok) return text(403, 'rejected')
        return json(200, encodeMlsGroupInfoAnswerWire(result.answer))
      }

      if (path === '/v1/mls/keypackage/publish') {
        const count = await publishMlsKeyPackages(ds, verifier, decodeMlsKeyPackagePublishWire(body))
        if (count === undefined) return text(403, 'rejected')
        return json(200, JSON.stringify({ count }))
      }

      if (path === '/v1/mls/keypackage/take') {
        const take = decodeMlsKeyPackageTakeWire(body)
        const taken = await takeMlsKeyPackages(ds, verifier, take, kid => isLiveDevice(take.identityId, kid))
        if (taken === undefined) return text(403, 'rejected')
        return json(200, encodeMlsKeyPackagesTakenWire(taken))
      }

      if (path === '/v1/mls/self-remove/submit') {
        const result = await submitMlsSelfRemove(ds, verifier, decodeMlsSelfRemoveSubmissionWire(body))
        return commitResponse(result)
      }

      if (path === '/v1/mls/pending-removals/clear') {
        const ok = await clearMlsPendingRemovals(ds, verifier, decodeMlsPendingRemovalsClearWire(body))
        if (!ok) return text(403, 'rejected')
        return json(200, '{}')
      }

      if (path === '/v1/mls/deliveries/pull') {
        const entries = await pullMlsDeliveries(ds, verifier, decodeMlsDeliveriesPullWire(body))
        if (entries === undefined) return text(403, 'rejected')
        return json(200, encodeMlsDeliveriesWire(entries))
      }

      if (path === '/v1/mls/keypackage/drop') {
        const ok = await dropMlsKeyPackages(ds, verifier, decodeMlsKeyPackageDropWire(body))
        if (!ok) return text(403, 'rejected')
        return json(200, '{}')
      }

      if (path === '/v1/mls/keypackage/count') {
        const count = await pullMlsKeyPackageCount(ds, verifier, decodeMlsKeyPackageCountPullWire(body))
        if (count === undefined) return text(403, 'rejected')
        return json(200, JSON.stringify({ count }))
      }

      if (path === '/v1/mls/groups-for') {
        const groups = await pullMlsGroupsFor(ds, verifier, decodeMlsGroupsForPullWire(body))
        if (groups === undefined) return text(403, 'rejected')
        return json(200, encodeMlsGroupsForWire(groups))
      }

      return text(404, 'Not found')
    } catch (error) {
      if (error instanceof MlsDsWireError || error instanceof MlsDsCapacityError || error instanceof RangeError || error instanceof TypeError) return text(400, error.message)
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
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('MLS DS HTTP body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('MLS DS HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}
function text(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } })
}
