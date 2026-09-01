/** Narrow HTTP boundary for MIMI provider endpoints implemented in Phase 0. */
import {
  authorizeKeyMaterial,
  authorizeKeyPackagePublish,
  authorizeUpdate,
  authorizeDeliveriesPull,
  authorizeDeliveriesWatch,
  authorizeSubmitMessage,
  keyMaterialResponse,
  type MimiSignatureVerifier,
} from './authorizer.ts'
import {
  decodeKeyMaterialRequestWire,
  decodeKeyPackagePublishWire,
  decodeDeliveriesPullRequestWire,
  decodeDeliveriesWatchRequestWire,
  decodeUpdateRoomRequestWire,
  decodeSubmitMessageRequestWire,
  encodeKeyMaterialResponseWire,
  encodeKeyPackagePublishResponseWire,
  encodeDeliveriesWire,
  encodeDeliveriesWatchTokenWire,
  encodeMimiErrorWire,
  encodeUpdateRoomResponseWire,
  encodeSubmitMessageResponseWire,
  MimiWireError,
  deliveryEntryWireJson,
} from './wire.ts'
import { frankMessage, verifyFrank } from './franking.ts'
import { createMimiProtocolDirectory, MIMI_PROTOCOL_DIRECTORY_PATH } from './directory.ts'
import { decodeMimiAbuseReportWire, encodeMimiAbuseReportWire, decodeMimiConsentEntryWire, decodeMimiIdentifierRequestWire, encodeMimiIdentifierResponseWire, noIdentifiers, type MimiIdentifierDirectory } from './federation.ts'
import { verifyMimiProviderRequest, type VerifiedProviderPeer } from './provider-transport.ts'
import { decodeMimiFanoutBatchWire, fanoutFingerprint } from './fanout.ts'
import { extractMimiMlsStateTransition } from './mls-appsync.ts'
import type { MimiAssetProxy } from './asset-proxy.ts'
import { MimiStoreCapacityError, MimiStoreStateError, type SqliteMimiStore } from './store.ts'
import type { MimiCredential, MimiDeploymentMode, MimiErrorResponse, UpdateRoomResponse } from './protocol-types.ts'
import type { MimiWatchTokenIssuer } from './watch-token.ts'

const MAX_BODY_BYTES = 1024 * 1024
const KEY_MATERIAL_PREFIX = '/keyMaterial/'
const UPDATE_PREFIX = '/update/'
const SUBMIT_MESSAGE_PREFIX = '/submitMessage/'
const REQUEST_CONSENT_PREFIX = '/requestConsent/'
const UPDATE_CONSENT_PREFIX = '/updateConsent/'
const IDENTIFIER_QUERY_PREFIX = '/identifierQuery/'
const NOTIFY_PREFIX = '/notify/'
const PROXY_DOWNLOAD_PREFIX = '/proxyDownload/'
const REPORT_ABUSE_PREFIX = '/reportAbuse/'
const DELIVERY_PULL_PATH = '/v1/mimi/deliveries/pull'
const DELIVERY_WATCH_PATH = '/v1/mimi/deliveries/watch'
const DELIVERY_STREAM_PATH = '/v1/mimi/deliveries/stream'
/** Biset's own extension (§5.1, PLAN_biset-mimi-server.md) -- the MIMI draft
 * leaves how a provider originally acquires a user's KeyPackages
 * unspecified, so without this route `keyMaterial` has nothing to ever
 * return and no client can be added to a room. */
const KEY_PACKAGE_PUBLISH_PATH = '/v1/mimi/keypackage/publish'

function isMimiHttpPath(path: string): boolean {
  return path.startsWith(KEY_MATERIAL_PREFIX) || path.startsWith(UPDATE_PREFIX)
    || path.startsWith(SUBMIT_MESSAGE_PREFIX)
    || path.startsWith(REQUEST_CONSENT_PREFIX) || path.startsWith(UPDATE_CONSENT_PREFIX) || path.startsWith(IDENTIFIER_QUERY_PREFIX)
    || path.startsWith(NOTIFY_PREFIX)
    || path.startsWith(PROXY_DOWNLOAD_PREFIX)
    || path.startsWith(REPORT_ABUSE_PREFIX)
    || path === DELIVERY_PULL_PATH || path === DELIVERY_WATCH_PATH || path === DELIVERY_STREAM_PATH || path === MIMI_PROTOCOL_DIRECTORY_PATH
    || path === KEY_PACKAGE_PUBLISH_PATH
}

/** The HTTPS listener/TLS terminator supplies a verified client-cert peer. */
export interface MimiFederationOptions {
  providerDomain: string
  authenticatePeer(request: Request): Promise<VerifiedProviderPeer | undefined>
  identifierDirectory?: MimiIdentifierDirectory
  assetProxy?: MimiAssetProxy
  now?: () => string
}

class MimiProviderAuthenticationError extends Error {}

/**
 * MIMI draft §5.2 / §5.3 provider-facing routes.  Biset's calls arrive from
 * local clients, so every body additionally uses the provider-internal
 * credential signature defined in authorizer.ts.
 */
export function createMimiHttpHandler(
  store: SqliteMimiStore,
  verifier: MimiSignatureVerifier,
  watchTokens: MimiWatchTokenIssuer,
  mode: MimiDeploymentMode,
  publicBaseUrl?: string,
  federation?: MimiFederationOptions,
  selfOwnerUser?: string,
): (request: Request) => Promise<Response> {
  return async request => {
    try {
      const path = new URL(request.url).pathname
      if (!isMimiHttpPath(path)) return error(404, 'not-found', 'Not found')
      if (mode === 'self' && isFederationPath(path)) return error(403, 'not-allowed', 'self-mode deployments do not expose federation endpoints')
      if (path === MIMI_PROTOCOL_DIRECTORY_PATH) {
        if (request.method !== 'GET') return error(405, 'bad-request', 'Method not allowed')
        return json(200, JSON.stringify(createMimiProtocolDirectory(publicBaseUrl ?? new URL(request.url).origin)))
      }
      if (path === DELIVERY_STREAM_PATH) {
        if (request.method !== 'GET') return error(405, 'bad-request', 'Method not allowed')
        return streamDeliveries(store, watchTokens, new URL(request.url))
      }
      if (path.startsWith(PROXY_DOWNLOAD_PREFIX)) {
        if (request.method !== 'GET') return error(405, 'bad-request', 'Method not allowed')
        await verifiedFederationPeer(request, federation)
        if (!federation?.assetProxy) return error(403, 'not-allowed', 'asset proxy is not configured')
        return federation.assetProxy.download(pathParameter(path, PROXY_DOWNLOAD_PREFIX, 'download URL'))
      }
      if (request.method !== 'POST') return error(405, 'bad-request', 'Method not allowed')
      const body = await requestText(request)

      if (path.startsWith(NOTIFY_PREFIX)) {
        const roomId = pathParameter(path, NOTIFY_PREFIX, 'room ID')
        const peer = await verifiedFederationPeer(request, federation)
        const batch = decodeMimiFanoutBatchWire(body)
        const result = store.acceptProviderFanout(roomId, peer.providerDomain, await fanoutFingerprint(body), batch.entries)
        if (result === 'noSuchRoom') return error(404, 'not-found', 'room does not exist')
        return new Response(null, { status: 201 })
      }

      if (path.startsWith(REPORT_ABUSE_PREFIX)) {
        const roomId = pathParameter(path, REPORT_ABUSE_PREFIX, 'room ID')
        const peer = await verifiedFederationPeer(request, federation)
        const report = decodeMimiAbuseReportWire(body)
        const keys = store.frankingKeys(roomId)
        if (!keys) return error(404, 'not-found', 'room does not exist')
        if (!report.messages.every(message => message.frank.context.roomUri === roomId && message.frank.context.acceptedTimestamp === message.acceptedTimestamp && verifyFrank(keys.signingPublicKey, message.frank))) return error(400, 'bad-request', 'abuse report contains invalid franking evidence')
        store.recordAbuseReport(roomId, peer.providerDomain, encodeMimiAbuseReportWire(report), federation!.now?.() ?? new Date().toISOString())
        return new Response(null, { status: 201 })
      }

      if (path.startsWith(REQUEST_CONSENT_PREFIX)) {
        const targetDomain = pathParameter(path, REQUEST_CONSENT_PREFIX, 'target domain')
        const peer = await verifiedFederationPeer(request, federation)
        if (!sameDomain(targetDomain, federation!.providerDomain)) return error(400, 'bad-request', 'target domain does not identify this provider')
        const entry = decodeMimiConsentEntryWire(body)
        if (entry.consentOperation !== 'request' && entry.consentOperation !== 'cancel') return error(400, 'bad-request', 'requestConsent requires request or cancel')
        store.recordConsent(entry, peer.providerDomain, federation!.now?.() ?? new Date().toISOString())
        return new Response(null, { status: 201 })
      }

      if (path.startsWith(UPDATE_CONSENT_PREFIX)) {
        const requesterDomain = pathParameter(path, UPDATE_CONSENT_PREFIX, 'requester domain')
        const peer = await verifiedFederationPeer(request, federation)
        if (!sameDomain(requesterDomain, federation!.providerDomain)) return error(400, 'bad-request', 'requester domain does not identify this provider')
        const entry = decodeMimiConsentEntryWire(body)
        if (entry.consentOperation !== 'grant' && entry.consentOperation !== 'revoke') return error(400, 'bad-request', 'updateConsent requires grant or revoke')
        store.recordConsent(entry, peer.providerDomain, federation!.now?.() ?? new Date().toISOString())
        return new Response(null, { status: 201 })
      }

      if (path.startsWith(IDENTIFIER_QUERY_PREFIX)) {
        const targetDomain = pathParameter(path, IDENTIFIER_QUERY_PREFIX, 'target domain')
        const peer = await verifiedFederationPeer(request, federation)
        if (!sameDomain(targetDomain, federation!.providerDomain)) return error(400, 'bad-request', 'identifier query domain does not identify this provider')
        const response = await (federation!.identifierDirectory ?? noIdentifiers).query(decodeMimiIdentifierRequestWire(body), peer.providerDomain)
        return json(200, encodeMimiIdentifierResponseWire(response))
      }

      if (path.startsWith(KEY_MATERIAL_PREFIX)) {
        const targetUser = pathParameter(path, KEY_MATERIAL_PREFIX, 'target user')
        const value = decodeKeyMaterialRequestWire(body)
        if (!credentialAllowed(value.requester, mode, selfOwnerUser)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (value.targetUser !== targetUser) return error(400, 'bad-request', 'target user path does not match request body')
        if (!(await authorizeKeyMaterial(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room membership was rejected')
        return json(200, encodeKeyMaterialResponseWire(keyMaterialResponse(value.targetUser, store.takeKeyPackages(value.targetUser, value.requiredCapabilities))))
      }

      if (path === KEY_PACKAGE_PUBLISH_PATH) {
        const value = decodeKeyPackagePublishWire(body)
        if (!credentialAllowed(value.credential, mode, selfOwnerUser)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (!(await authorizeKeyPackagePublish(verifier, value))) return error(403, 'unauthorized', 'request signature was rejected')
        const published = store.publishKeyPackages(value)
        return json(200, encodeKeyPackagePublishResponseWire({ published }))
      }

      if (path.startsWith(UPDATE_PREFIX)) {
        const roomId = pathParameter(path, UPDATE_PREFIX, 'room ID')
        const value = decodeUpdateRoomRequestWire(body)
        if (!credentialAllowed(value.sender, mode, selfOwnerUser) || (mode === 'self' && !selfUpdateOwned(value, selfOwnerUser))) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential or room state`)
        if (value.roomId !== roomId) return error(400, 'bad-request', 'room ID path does not match request body')
        if (!(await authorizeUpdate(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        // Existing rooms derive provider-visible state from an MLS Public
        // Commit. Initial room creation remains a one-time envelope until the
        // MIMI room-policy component has a stable initial-state assignment.
        const mlsTransition = store.room(roomId) === undefined
          ? undefined
          : value.bundle.kind === 'commit'
            ? extractMimiMlsStateTransition(value.bundle.proposalOrCommit)
            : undefined
        const result = store.submitUpdate(value, mlsTransition)
        if (result.ok) return json(200, encodeUpdateRoomResponseWire({ status: 'success', acceptedTimestamp: value.submittedAt }))
        return updateError(result.reason, result.message, result.currentEpoch)
      }

      if (path.startsWith(SUBMIT_MESSAGE_PREFIX)) {
        const roomId = pathParameter(path, SUBMIT_MESSAGE_PREFIX, 'room ID')
        const value = decodeSubmitMessageRequestWire(body)
        if (!credentialAllowed(value.sender, mode, selfOwnerUser)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (value.roomId !== roomId) return error(400, 'bad-request', 'room ID path does not match request body')
        if (!(await authorizeSubmitMessage(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        const keys = store.frankingKeys(roomId)
        if (!keys) return error(404, 'not-found', 'room does not exist')
        const acceptedTimestamp = Date.parse(value.submittedAt)
        if (!Number.isFinite(acceptedTimestamp) || acceptedTimestamp < 0) return error(400, 'bad-request', 'submittedAt must be a valid post-1970 timestamp')
        const senderUri = credentialUser(value.sender)
        const frank = frankMessage(keys, { aad: value.frankAAD, senderUri, roomUri: roomId, acceptedTimestamp: String(acceptedTimestamp), ciphersuite: value.frankingSignatureCiphersuite })
        const result = store.submitMessage(roomId, senderUri, value.epoch, value.appMessage, frank, value.submittedAt)
        if (!result.ok) return json(409, encodeSubmitMessageResponseWire({ status: 'epochTooOld', currentEpoch: result.currentEpoch }))
        return json(200, encodeSubmitMessageResponseWire({ status: 'accepted', acceptedTimestamp: value.submittedAt, frank }))
      }

      if (path === DELIVERY_PULL_PATH) {
        const value = decodeDeliveriesPullRequestWire(body)
        if (!credentialAllowed(value.requester, mode, selfOwnerUser)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (!(await authorizeDeliveriesPull(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        return json(200, encodeDeliveriesWire(store.deliveriesSince(value.roomId, credentialUser(value.requester), value.afterSeq) ?? []))
      }

      if (path === DELIVERY_WATCH_PATH) {
        const value = decodeDeliveriesWatchRequestWire(body)
        if (!credentialAllowed(value.requester, mode, selfOwnerUser)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (!(await authorizeDeliveriesWatch(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        return json(200, encodeDeliveriesWatchTokenWire(watchTokens.issue(value.roomId, credentialUser(value.requester))))
      }

      return error(404, 'not-found', 'Not found')
    } catch (cause) {
      if (cause instanceof MimiProviderAuthenticationError) return error(403, 'unauthorized', 'provider mTLS authentication or identity binding was rejected')
      if (cause instanceof MimiWireError || cause instanceof MimiStoreCapacityError || cause instanceof MimiStoreStateError || cause instanceof RangeError || cause instanceof TypeError) {
        return error(400, 'bad-request', cause.message)
      }
      return error(500, 'internal-error', 'Internal server error')
    }
  }
}

async function verifiedFederationPeer(request: Request, federation: MimiFederationOptions | undefined): Promise<VerifiedProviderPeer> {
  if (!federation) throw new MimiProviderAuthenticationError()
  const peer = await federation.authenticatePeer(request)
  if (!peer) throw new MimiProviderAuthenticationError()
  try { verifyMimiProviderRequest(request, federation.providerDomain, peer) } catch { throw new MimiProviderAuthenticationError() }
  return peer
}

function sameDomain(left: string, right: string): boolean { return left.toLowerCase().replace(/\.$/, '') === right.toLowerCase().replace(/\.$/, '') }

function credentialAllowed(credential: MimiCredential, mode: MimiDeploymentMode, selfOwnerUser: string | undefined): boolean {
  if (mode === 'anon') return credential.kind === 'pseudonymous'
  return credential.kind === 'visible' && (mode !== 'self' || credential.user === selfOwnerUser)
}

function credentialUser(credential: MimiCredential): string {
  return credential.kind === 'visible' ? credential.user : credential.userPseudonym
}

function selfUpdateOwned(value: import('./protocol-types.ts').UpdateRoomRequest, selfOwnerUser: string | undefined): boolean {
  if (!selfOwnerUser) return false
  const states = [value.initialState, value.stateUpdate]
  return states.every(state => state === undefined || (state.memberCredentials === undefined || state.memberCredentials.every(credential => credential.kind === 'visible' && credential.user === selfOwnerUser)) && (state.participantList === undefined || state.participantList.participants.every(participant => participant.user === selfOwnerUser)))
}

function isFederationPath(path: string): boolean {
  return path.startsWith(REQUEST_CONSENT_PREFIX) || path.startsWith(UPDATE_CONSENT_PREFIX) || path.startsWith(IDENTIFIER_QUERY_PREFIX) || path.startsWith(NOTIFY_PREFIX) || path.startsWith(PROXY_DOWNLOAD_PREFIX) || path.startsWith(REPORT_ABUSE_PREFIX)
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
