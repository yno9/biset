/**
 * Shared MIMI provider types.  These model the server-visible state and the
 * narrow client-to-hub boundary; `wire.ts` is solely responsible for turning
 * their binary fields into JSON/base64url.
 *
 * The MIMI draft's TLS presentation syntax is intentionally not reproduced
 * here.  The draft explicitly leaves endpoint encoding open, while biset
 * uses JSON over HTTP internally (PLAN_biset-mimi-server.md §3).
 */

/** URI-shaped identifiers are kept opaque at this boundary. */
export type MimiRoomId = string
export type MimiUserUri = string
export type MimiClientUri = string
export type MimiProviderUri = string

/** Decimal uint64, represented as a string so JSON never loses precision. */
export type MimiEpoch = string

export type MimiProtocolVersion = 'mls10'

/** The basic, non-MMR MLS credential accepted during Phase 0 and Phase 1. */
export interface VisibleCredential {
  kind: 'visible'
  /** The user identity the credential binds (normally a DID URI). */
  user: MimiUserUri
  /** The particular MLS client/device represented by the credential. */
  client: MimiClientUri
  /** Serialized MLS Credential.  Its format is interpreted by MLS, not here. */
  credential: Uint8Array
  /** MLS SignaturePublicKey used for signed client-to-hub requests. */
  signaturePublicKey: Uint8Array
}

/**
 * Phase 2's MMR credential.  It is declared now so persisted and wire types
 * do not need a breaking shape change; Phase 0 accepts only VisibleCredential.
 */
export interface PseudonymousCredential {
  kind: 'pseudonymous'
  clientPseudonym: MimiClientUri
  userPseudonym: MimiUserUri
  signaturePublicKey: Uint8Array
  identityLinkCiphertext: Uint8Array
  signature: Uint8Array
}

export type MimiCredential = VisibleCredential | PseudonymousCredential

/** One user and its exactly-one room role (draft §7.5). */
export interface UserRolePair {
  user: MimiUserUri
  roleIndex: number
  /**
   * Client identifiers currently represented by MLS leaves.  The participant
   * list itself is user-level, so this is server bookkeeping rather than a
   * replacement for the draft's UserRolePair encoding.
   */
  clientIds?: MimiClientUri[]
}

/** draft §7.5's ParticipantListData component. */
export interface ParticipantListData {
  participants: UserRolePair[]
}

export interface RichDescription {
  /** Empty means `text/plain;charset=utf-8`, per draft §7.6. */
  mediaType: string
  languageTag: string
  content: string
}

/** draft §7.6 room metadata component. */
export interface RoomMetadata {
  roomUri: MimiRoomId
  roomName: string
  descriptions?: RichDescription[]
  roomAvatar?: string
  roomSubject?: string
  roomMood?: string
}

/**
 * Provider-visible state for a hubbed room (draft §4.3.1).  MLS group state
 * is client-owned; the hub persists only the public GroupInfo/tree material
 * it needs to serve future protocol operations.
 */
export interface RoomState {
  roomId: MimiRoomId
  protocol: MimiProtocolVersion
  epoch: MimiEpoch
  basePolicy: Uint8Array
  participantList: ParticipantListData
  metadata: RoomMetadata
  groupInfo?: Uint8Array
  ratchetTree?: Uint8Array
  createdAt: string
  updatedAt: string
}

/** Compatibility constraints supplied when claiming MLS KeyPackages. */
export interface MlsRequiredCapabilities {
  credentialTypes?: number[]
  proposalTypes?: number[]
  extensions?: number[]
}

/** One unconsumed MLS KeyPackage in the provider's publication directory. */
export interface PublishedKeyPackage {
  reference: Uint8Array
  user: MimiUserUri
  client: MimiClientUri
  keyPackage: Uint8Array
  capabilities?: MlsRequiredCapabilities
  publishedAt: string
  expiresAt?: string
  sourceProvider?: MimiProviderUri
}

/** Internal/provider-local publication operation; client-server publication is outside the MIMI draft. */
export interface KeyPackagePublishRequest {
  version: 1
  credential: MimiCredential
  packages: PublishedKeyPackage[]
  publishedAt: string
  signature: Uint8Array
}

/** draft §5.2 KeyMaterialRequest, plus biset's client-to-hub signature. */
export interface KeyMaterialRequest {
  version: 1
  protocol: MimiProtocolVersion
  requestingUser: MimiUserUri
  targetUser: MimiUserUri
  /** Required for all Phase 0 claims, so the hub can retain routing state. */
  roomId: MimiRoomId
  acceptableCiphersuites: number[]
  requiredCapabilities: MlsRequiredCapabilities
  requester: VisibleCredential
  signature: Uint8Array
}

export type KeyMaterialUserStatus =
  | 'success'
  | 'partialSuccess'
  | 'incompatibleProtocol'
  | 'noCompatibleMaterial'
  | 'userUnknown'
  | 'noConsent'
  | 'noConsentForThisRoom'
  | 'userDeleted'

export type KeyMaterialClientStatus = 'success' | 'keyMaterialExhausted' | 'nothingCompatible'

export interface ClientKeyMaterial {
  client: MimiClientUri
  status: KeyMaterialClientStatus
  keyPackage?: Uint8Array
  capabilities?: MlsRequiredCapabilities
}

export interface KeyMaterialResponse {
  protocol: MimiProtocolVersion
  user: MimiUserUri
  status: KeyMaterialUserStatus
  clients: ClientKeyMaterial[]
}

/** MIMI update's committed/proposed MLS handshake material (draft §5.3). */
export interface HandshakeBundle {
  kind: 'commit' | 'proposal'
  proposalOrCommit: Uint8Array
  /** Additional proposals are valid only when `kind === 'proposal'`. */
  moreProposals?: Uint8Array[]
  welcome?: Uint8Array
  groupInfo?: Uint8Array
  ratchetTree?: Uint8Array
}

/**
 * Biset's authenticated client-to-hub representation of draft §5.3's
 * UpdateRequest.  The draft does not specify provider-internal client
 * authentication, hence sender and signature are explicit here.
 */
export interface UpdateRoomRequest {
  version: 1
  protocol: MimiProtocolVersion
  roomId: MimiRoomId
  sender: VisibleCredential
  epoch: MimiEpoch
  bundle: HandshakeBundle
  /** Present when this is the initial commit that creates the room. */
  initialState?: Pick<RoomState, 'basePolicy' | 'participantList' | 'metadata'>
  submittedAt: string
  signature: Uint8Array
}

export type UpdateResponseCode = 'success' | 'wrongEpoch' | 'notAllowed' | 'invalidProposal'

export interface UpdateRoomResponse {
  status: UpdateResponseCode
  acceptedTimestamp?: string
  currentEpoch?: MimiEpoch
  invalidProposals?: Uint8Array[]
  errorDescription?: string
}

/** An opaque item delivered from a hub to one of its local clients. */
export type MimiDeliveryKind = 'commit' | 'proposal' | 'welcome' | 'application'

export interface MimiDeliveryEntry {
  seq: number
  kind: MimiDeliveryKind
  payload: Uint8Array
  epoch: MimiEpoch
  acceptedAt: string
}

export interface DeliveriesPullRequest {
  version: 1
  roomId: MimiRoomId
  requester: VisibleCredential
  afterSeq: number
  requestedAt: string
  signature: Uint8Array
}

export interface DeliveriesWatchRequest {
  version: 1
  roomId: MimiRoomId
  requester: VisibleCredential
  requestedAt: string
  signature: Uint8Array
}

export interface DeliveriesWatchToken {
  token: string
  expiresAt: string
}

/** Stable, non-sensitive machine-readable error shape for every endpoint. */
export interface MimiErrorResponse {
  error: 'bad-request' | 'unauthorized' | 'not-found' | 'conflict' | 'not-allowed' | 'internal-error'
  message: string
}
