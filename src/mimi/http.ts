/** Narrow HTTP boundary for MIMI provider endpoints implemented in Phase 0. */
import {
  authorizeGroupInfoRequest,
  authorizeExternalJoinUpdate,
  authorizeKeyMaterial,
  authorizeKeyPackagePublish,
  authorizeUpdate,
  authorizeDeliveriesPull,
  authorizeDeliveriesWatch,
  authorizeSubmitMessage,
  authorizeSubmitVaultCheckpoint,
  keyMaterialResponse,
  userIsRoomParticipant,
  type MimiSignatureVerifier,
} from './authorizer.ts'
import {
  decodeGroupInfoRequestWire,
  decodeKeyMaterialRequestWire,
  decodeKeyPackagePublishWire,
  decodeDeliveriesPullRequestWire,
  decodeDeliveriesWatchRequestWire,
  decodeUpdateRoomRequestWire,
  decodeSubmitMessageRequestWire,
  decodeSubmitVaultCheckpointRequestWire,
  encodeGroupInfoResponseWire,
  encodeKeyMaterialResponseWire,
  encodeKeyPackagePublishResponseWire,
  encodeDeliveriesWire,
  encodeDeliveriesWatchTokenWire,
  encodeMimiErrorWire,
  encodeFrankingAgentDataWire,
  encodeUpdateRoomResponseWire,
  encodeSubmitMessageResponseWire,
  encodeSubmitVaultCheckpointResponseWire,
  MimiWireError,
  deliveryEntryWireJson,
} from './wire.ts'
import { frankMessage, verifyFrank } from './franking.ts'
import { sealGroupInfoResponse } from './group-info.ts'
import { createMimiProtocolDirectory, MIMI_PROTOCOL_DIRECTORY_PATH } from './directory.ts'
import { decodeMimiAbuseReportWire, encodeMimiAbuseReportWire, decodeMimiConsentEntryWire, decodeMimiIdentifierRequestWire, encodeMimiIdentifierResponseWire, noIdentifiers, type MimiIdentifierDirectory } from './federation.ts'
import { verifyMimiProviderRequest, type VerifiedProviderPeer } from './provider-transport.ts'
import { decodeMimiFanoutBatchWire, fanoutDeliveries, fanoutFingerprint, MimiFanoutDispatcher, type MimiFanoutMessage } from './fanout.ts'
import { mimiUriProviderDomain } from './mimi-uri.ts'
import { resolveMimiProviderBaseUrl } from './provider-directory-client.ts'
import { extractMimiMlsStateTransition } from './mls-appsync.ts'
import { decodeMlsMessage, encodeMlsMessage } from '../mls/vendor/index.ts'
import { decodeWelcome } from '../mls/vendor/welcome.ts'
import { defaultAuthenticationService } from '../mls/vendor/authenticationService.ts'
import { applyPublicCommit } from '../mls/vendor/publicGroupState.ts'
import { mlsSuite } from '../mls/suite.ts'
import { bootstrapPublicGroupStateFromGroupInfo } from './mls-group-info-bootstrap.ts'
import { equalBytes } from '../shared/protocol/canonical.ts'
import type { MimiAssetProxy } from './asset-proxy.ts'
import { MimiStoreCapacityError, MimiStoreStateError, type SqliteMimiStore } from './store.ts'
import type { GroupInfoResponse, MimiCredential, MimiDeliveryEntry, MimiDeploymentMode, MimiErrorResponse, UpdateRoomRequest, UpdateRoomResponse } from './protocol-types.ts'
import type { MimiWatchTokenIssuer } from './watch-token.ts'

const MAX_BODY_BYTES = 1024 * 1024
const KEY_MATERIAL_PREFIX = '/keyMaterial/'
const UPDATE_PREFIX = '/update/'
const GROUP_INFO_PREFIX = '/groupInfo/'
const SUBMIT_MESSAGE_PREFIX = '/submitMessage/'
const SUBMIT_VAULT_CHECKPOINT_PREFIX = '/v1/mimi/vault-checkpoint/'
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
const FRANKING_AGENT_PREFIX = '/v1/mimi/franking-agent/'

function isMimiHttpPath(path: string): boolean {
  return path.startsWith(KEY_MATERIAL_PREFIX) || path.startsWith(UPDATE_PREFIX) || path.startsWith(GROUP_INFO_PREFIX)
    || path.startsWith(SUBMIT_MESSAGE_PREFIX)
    || path.startsWith(SUBMIT_VAULT_CHECKPOINT_PREFIX)
    || path.startsWith(REQUEST_CONSENT_PREFIX) || path.startsWith(UPDATE_CONSENT_PREFIX) || path.startsWith(IDENTIFIER_QUERY_PREFIX)
    || path.startsWith(NOTIFY_PREFIX)
    || path.startsWith(PROXY_DOWNLOAD_PREFIX)
    || path.startsWith(REPORT_ABUSE_PREFIX)
    || path === DELIVERY_PULL_PATH || path === DELIVERY_WATCH_PATH || path === DELIVERY_STREAM_PATH || path === MIMI_PROTOCOL_DIRECTORY_PATH
    || path === KEY_PACKAGE_PUBLISH_PATH || path.startsWith(FRANKING_AGENT_PREFIX)
}

/** The HTTPS listener/TLS terminator supplies a verified client-cert peer. */
export interface MimiFederationOptions {
  providerDomain: string
  authenticatePeer(request: Request): Promise<VerifiedProviderPeer | undefined>
  identifierDirectory?: MimiIdentifierDirectory
  assetProxy?: MimiAssetProxy
  now?: () => string
  /** Absent: this hub only ever receives federation traffic (inbound
   * `/notify`, requestConsent, etc.) and never initiates it -- rooms that
   * gain a remote participant simply never fan out to them. Present: after
   * a local room update/message is accepted, its MLSMessage bytes are
   * pushed to every remote provider represented in the room's current
   * participant list, best-effort (fire-and-forget; a peer being
   * unreachable never fails the local accept -- see dispatchFanout). */
  outbound?: {
    dispatcher: MimiFanoutDispatcher
    /** Defaults to resolveMimiProviderBaseUrl (directory-based discovery);
     * overridable for tests. */
    resolveProviderBaseUrl?(domain: string): Promise<string>
  }
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
  allowExternalJoin = false,
): (request: Request) => Promise<Response> {
  return async request => {
    try {
      const path = new URL(request.url).pathname
      if (!isMimiHttpPath(path)) return error(404, 'not-found', 'Not found')
      if (path === MIMI_PROTOCOL_DIRECTORY_PATH) {
        if (request.method !== 'GET') return error(405, 'bad-request', 'Method not allowed')
        return json(200, JSON.stringify(createMimiProtocolDirectory(publicBaseUrl ?? new URL(request.url).origin)))
      }
      if (path === DELIVERY_STREAM_PATH) {
        if (request.method !== 'GET') return error(405, 'bad-request', 'Method not allowed')
        return streamDeliveries(store, watchTokens, new URL(request.url))
      }
      if (path.startsWith(FRANKING_AGENT_PREFIX)) {
        if (request.method !== 'GET') return error(405, 'bad-request', 'Method not allowed')
        const roomId = pathParameter(path, FRANKING_AGENT_PREFIX, 'room ID')
        const keys = store.prepareFrankingKeys(roomId)
        // This provider credential is the public HTTPS identity asserted by
        // the directory. Deployments with a real MLS credential may replace
        // this opaque byte string without changing the component wire shape.
        return json(200, encodeFrankingAgentDataWire({ frankingSignatureKey: keys.signingPublicKey, credential: new TextEncoder().encode(publicBaseUrl ?? new URL(request.url).origin) }))
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
        const room = store.room(roomId)
        // '0' is a harmless placeholder epoch when the room is unknown --
        // it only ever affects a Welcome entry's reported epoch, and the
        // commit entry (which bootstrap extraction actually reads) always
        // carries its own real epoch regardless (fanout.ts's classify()).
        const entries = fanoutDeliveries(batch, room?.epoch ?? '0')
        const bootstrap = room === undefined ? bootstrapTransitionFromFanout(entries) : undefined
        const result = store.acceptProviderFanout(roomId, peer.providerDomain, await fanoutFingerprint(body), entries, bootstrap)
        if (result === 'noSuchRoom') return error(404, 'not-found', 'room does not exist')
        if (result === 'invalidBootstrap') return error(400, 'bad-request', 'first-contact fanout is not a self-sufficient room-creation commit')
        return new Response(null, { status: 201 })
      }

      if (path.startsWith(GROUP_INFO_PREFIX)) {
        const roomId = pathParameter(path, GROUP_INFO_PREFIX, 'room ID')
        // Off by default: a GroupInfo ratchet tree discloses every member's
        // real credential to whoever fetches it. Only a deployment dedicated
        // to Self Group traffic (deployment.ts's allowExternalJoin) turns
        // this on, where the only possible members are the room's own owner.
        if (!allowExternalJoin) return error(403, 'not-allowed', 'external joins are disabled by this provider privacy policy')
        const value = decodeGroupInfoRequestWire(body)
        if (!(await authorizeGroupInfoRequest(store, verifier, value))) return error(403, 'unauthorized', 'request signature was rejected')
        const room = store.room(roomId)
        if (!room) return json(200, encodeGroupInfoResponseWire({ version: 1, roomId, status: 'noSuchRoom' }))
        if (!userIsRoomParticipant(room, credentialUser(value.requester)) || !room.groupInfo) {
          return json(200, encodeGroupInfoResponseWire({ version: 1, roomId, status: 'notAuthorized' }))
        }
        const keys = store.frankingKeys(roomId)
        if (!keys) return json(200, encodeGroupInfoResponseWire({ version: 1, roomId, status: 'notAuthorized' }))
        const response: GroupInfoResponse = await sealGroupInfoResponse(
          roomId, room.groupInfo, room.ratchetTree, value.groupInfoPublicKey,
          room.frankingAgent?.credential ?? new TextEncoder().encode(publicBaseUrl ?? new URL(request.url).origin), keys,
        )
        return json(200, encodeGroupInfoResponseWire(response))
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
        if (!credentialAllowed(value.requester, mode)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (value.targetUser !== targetUser) return error(400, 'bad-request', 'target user path does not match request body')
        if (!(await authorizeKeyMaterial(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room membership was rejected')
        return json(200, encodeKeyMaterialResponseWire(keyMaterialResponse(value.targetUser, store.takeKeyPackages(value.targetUser, value.requiredCapabilities))))
      }

      if (path === KEY_PACKAGE_PUBLISH_PATH) {
        const value = decodeKeyPackagePublishWire(body)
        if (!credentialAllowed(value.credential, mode)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (!(await authorizeKeyPackagePublish(verifier, value))) return error(403, 'unauthorized', 'request signature was rejected')
        const published = store.publishKeyPackages(value)
        return json(200, encodeKeyPackagePublishResponseWire({ published }))
      }

      if (path.startsWith(UPDATE_PREFIX)) {
        const roomId = pathParameter(path, UPDATE_PREFIX, 'room ID')
        const value = decodeUpdateRoomRequestWire(body)
        if (!credentialAllowed(value.sender, mode)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (value.roomId !== roomId) return error(400, 'bad-request', 'room ID path does not match request body')
        if (!(await authorizeUpdate(store, verifier, value)) && !(allowExternalJoin && await authorizeExternalJoinUpdate(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        // Existing rooms derive provider-visible state from an MLS Public
        // Commit. Initial room creation remains a one-time envelope until the
        // MIMI room-policy component has a stable initial-state assignment.
        const mlsTransition = value.bundle.kind === 'commit'
          ? extractMimiMlsStateTransition(value.bundle.proposalOrCommit)
          : undefined
        // The hub key alone is not its complete AppData identity: bind its
        // advertised credential to this exact HTTPS origin as well, so a
        // creator cannot substitute an arbitrary agent credential while
        // retaining a hub-generated public key.
        if (value.initialState !== undefined && mlsTransition?.frankingAgent !== undefined
          && !equalBytes(mlsTransition.frankingAgent.credential, new TextEncoder().encode(publicBaseUrl ?? new URL(request.url).origin))) {
          return error(400, 'bad-request', 'franking_signature_key credential does not match this hub')
        }
        const result = store.submitUpdate(value, mlsTransition)
        if (result.ok) {
          const acceptedAt = Date.parse(value.submittedAt)
          if (Number.isFinite(acceptedAt) && acceptedAt >= 0) {
            const timestamp = String(acceptedAt)
            // A Welcome FanoutMessage requires ratchetTreeOption (fanout.ts's
            // validate()) -- skip fanning it out (still fans out the commit)
            // if the bundle has a welcome but no accompanying ratchet_tree.
            // HandshakeBundle.welcome is a bare Welcome struct (the shape
            // store.ts already stores it as for local delivery), but a
            // FanoutMessage.message must be a *complete* MLSMessage (fanout.ts
            // classify()) -- decode and re-wrap it.
            const welcomeMessage = (() => {
              if (!value.bundle.welcome || !value.bundle.ratchetTree) return undefined
              const decoded = decodeWelcome(value.bundle.welcome, 0)
              if (!decoded || decoded[1] !== value.bundle.welcome.length) return undefined
              return { timestamp, protocol: 'mls10' as const, message: encodeMlsMessage({ version: 'mls10', wireformat: 'mls_welcome', welcome: decoded[0] }), ratchetTreeOption: value.bundle.ratchetTree }
            })()
            const messages: MimiFanoutMessage[] = [
              { timestamp, protocol: 'mls10', message: value.bundle.proposalOrCommit, ...(value.bundle.kind === 'proposal' && value.bundle.moreProposals ? { moreProposals: value.bundle.moreProposals } : {}) },
              ...(welcomeMessage ? [welcomeMessage] : []),
            ]
            dispatchFanout(store, federation, roomId, messages)
          }
          void trackMlsPublicState(store, roomId, value)
          return json(200, encodeUpdateRoomResponseWire({ status: 'success', acceptedTimestamp: value.submittedAt }))
        }
        return updateError(result.reason, result.message, result.currentEpoch)
      }

      if (path.startsWith(SUBMIT_MESSAGE_PREFIX)) {
        const roomId = pathParameter(path, SUBMIT_MESSAGE_PREFIX, 'room ID')
        const value = decodeSubmitMessageRequestWire(body)
        if (!credentialAllowed(value.sender, mode)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (value.roomId !== roomId) return error(400, 'bad-request', 'room ID path does not match request body')
        if (!(await authorizeSubmitMessage(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        const keys = store.frankingKeys(roomId)
        if (!keys) return error(404, 'not-found', 'room does not exist')
        const acceptedTimestamp = Date.parse(value.submittedAt)
        if (!Number.isFinite(acceptedTimestamp) || acceptedTimestamp < 0) return error(400, 'bad-request', 'submittedAt must be a valid post-1970 timestamp')
        const senderUri = credentialUser(value.sender)
        const frank = frankMessage(keys, { aad: value.frankAAD, senderUri, roomUri: roomId, acceptedTimestamp: String(acceptedTimestamp), ciphersuite: value.frankingSignatureCiphersuite })
        const result = store.submitMessage(roomId, senderUri, value.epoch, value.appMessage, frank, value.submittedAt, value.deliveryId)
        if (!result.ok) return json(409, encodeSubmitMessageResponseWire({ status: 'epochTooOld', currentEpoch: result.currentEpoch }))
        dispatchFanout(store, federation, roomId, [{ timestamp: String(acceptedTimestamp), protocol: 'mls10', message: value.appMessage, frank }])
        return json(200, encodeSubmitMessageResponseWire({ status: 'accepted', acceptedTimestamp: value.submittedAt, frank }))
      }

      if (path.startsWith(SUBMIT_VAULT_CHECKPOINT_PREFIX)) {
        const roomId = pathParameter(path, SUBMIT_VAULT_CHECKPOINT_PREFIX, 'room ID')
        const value = decodeSubmitVaultCheckpointRequestWire(body)
        if (!credentialAllowed(value.sender, mode)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (value.roomId !== roomId) return error(400, 'bad-request', 'room ID path does not match request body')
        if (!(await authorizeSubmitVaultCheckpoint(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        const result = store.submitVaultCheckpoint(value)
        if (result.ok) return json(200, encodeSubmitVaultCheckpointResponseWire({ status: 'accepted', acceptedTimestamp: result.entry.acceptedAt }))
        return json(result.reason === 'conflict' ? 409 : 409, encodeSubmitVaultCheckpointResponseWire({ status: result.reason, currentEpoch: result.currentEpoch }))
      }

      if (path === DELIVERY_PULL_PATH) {
        const value = decodeDeliveriesPullRequestWire(body)
        if (!credentialAllowed(value.requester, mode)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
        if (!(await authorizeDeliveriesPull(store, verifier, value))) return error(403, 'unauthorized', 'request signature or room credential was rejected')
        return json(200, encodeDeliveriesWire(store.deliveriesSince(value.roomId, credentialUser(value.requester), value.afterSeq) ?? []))
      }

      if (path === DELIVERY_WATCH_PATH) {
        const value = decodeDeliveriesWatchRequestWire(body)
        if (!credentialAllowed(value.requester, mode)) return error(403, 'not-allowed', `${mode}-mode deployment rejected this credential`)
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

/**
 * A room's genesis commit is self-sufficient bootstrap material -- see
 * store.ts's createFromProviderFanout for exactly what "self-sufficient"
 * requires and what a later, non-genesis add-commit is still missing.
 * Returns undefined (not a throw) for any commit that doesn't extract
 * cleanly, so an unknown room with unusable fanout content is refused the
 * same way as one with no bootstrap material at all.
 */
function bootstrapTransitionFromFanout(entries: MimiDeliveryEntry[]) {
  const commit = entries.find(entry => entry.kind === 'commit')
  if (!commit) return undefined
  try { return extractMimiMlsStateTransition(commit.payload) } catch { return undefined }
}

/**
 * Fire-and-forget federation fanout after a local room update/message is
 * accepted. Dispatches the same batch to every remote provider domain
 * represented in the room's *current* participant list -- deliberately not
 * filtered per-message (a Welcome, say, is only meaningful to its one new
 * member's provider), matching the existing local-delivery model where
 * every room participant receives every delivery and simply skips what
 * isn't theirs (store.ts's own `welcome` append is room-wide, not
 * per-recipient). A peer being unreachable, slow, or on an unconfigured
 * domain never fails or delays the local accept response -- this always
 * runs detached from the request handler and only logs on failure.
 */
/**
 * Best-effort, fire-and-forget MLS public tree tracking (PLAN_biset-mimi-
 * server.md §21) after a locally-accepted `/update`. `Database.transaction`
 * (store.submitUpdate) must stay synchronous, so this real crypto work runs
 * detached, after the accept has already happened and its response is on
 * its way -- mirroring dispatchFanout's own shape just above.
 *
 * A new room only starts being tracked if its creator supplied a verifiable
 * `bundle.groupInfo` (optional; rooms without one behave exactly as before
 * this feature existed). An existing tracked room's state is kept current
 * by applying each subsequent commit -- if that ever fails for any reason
 * (a structurally-invalid commit, a bug, anything), tracking is dropped for
 * that room rather than surfaced as an error: this mechanism only ever
 * *adds* an extra, tree-verified path credentialMatchesRoom (authorizer.ts)
 * can use, on top of the sidecar check every room already had, so losing
 * tracking can never regress previously-working traffic.
 */
function trackMlsPublicState(store: SqliteMimiStore, roomId: string, value: UpdateRoomRequest): Promise<void> {
  return (async () => {
    try {
      const suite = await mlsSuite()
      const existing = value.initialState === undefined ? store.mlsPublicState(roomId) : undefined
      if (value.initialState !== undefined) {
        if (!value.bundle.groupInfo) return
        store.saveMlsPublicState(roomId, await bootstrapPublicGroupStateFromGroupInfo(value.bundle.groupInfo, defaultAuthenticationService, suite))
        return
      }
      if (!existing || value.bundle.kind !== 'commit') return
      const decoded = decodeMlsMessage(value.bundle.proposalOrCommit, 0)
      if (!decoded || decoded[1] !== value.bundle.proposalOrCommit.length || decoded[0].wireformat !== 'mls_public_message') { store.clearMlsPublicState(roomId); return }
      store.saveMlsPublicState(roomId, await applyPublicCommit(existing, decoded[0].publicMessage, defaultAuthenticationService, suite))
    } catch (cause) {
      console.warn(`[mimi/mls-public-state] tracking for room ${roomId} stopped:`, cause)
      // Best-effort cleanup of a best-effort mechanism: if the store itself
      // is already gone (e.g. a test closed its :memory: database right
      // after the HTTP response it triggered this detached work from --
      // deployment.close() has always been safe to call immediately after
      // any prior request, and this fire-and-forget tracking must not
      // change that), swallow this too rather than produce a second,
      // unhandled rejection on top of the first warning.
      try { store.clearMlsPublicState(roomId) } catch { /* store already closed; nothing left to clean up */ }
    }
  })()
}

function dispatchFanout(store: SqliteMimiStore, federation: MimiFederationOptions | undefined, roomId: string, messages: MimiFanoutMessage[]): void {
  if (!federation?.outbound || messages.length === 0) return
  const room = store.room(roomId)
  if (!room) return
  const resolve = federation.outbound.resolveProviderBaseUrl ?? resolveMimiProviderBaseUrl
  const remoteDomains = new Set(
    room.participantList.participants
      .map(participant => { try { return mimiUriProviderDomain(participant.user) } catch { return undefined } })
      .filter((domain): domain is string => domain !== undefined && !sameDomain(domain, federation.providerDomain)),
  )
  for (const domain of remoteDomains) {
    void (async () => {
      try {
        const providerBaseUrl = await resolve(domain)
        await federation.outbound!.dispatcher.send({ providerBaseUrl, roomId }, { messages })
      } catch (cause) {
        console.warn(`[mimi/federation] fanout of room ${roomId} to ${domain} failed:`, cause)
      }
    })()
  }
}

function credentialAllowed(credential: MimiCredential, mode: MimiDeploymentMode): boolean {
  return mode === 'anon' ? credential.kind === 'pseudonymous' : credential.kind === 'visible'
}

function credentialUser(credential: MimiCredential): string {
  return credential.kind === 'visible' ? credential.user : credential.userPseudonym
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
