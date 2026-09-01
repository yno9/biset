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
/**
 * Process-wide isolation mode; never a room-level switch. There is no
 * distinct 'self' mode: a Self Group (one user's own multiple devices) is
 * just an ordinary 'normal'-mode room whose participant list happens to
 * have one user. A dedicated deployment for that traffic (separate from
 * third-party groups, for availability isolation -- PLAN_biset-mimi-server.md
 * §14/§18) runs this exact 'normal' code with `allowExternalJoin: true`
 * (deployment.ts), not a different mode.
 */
export type MimiDeploymentMode = 'normal' | 'anon'

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
}

export type MimiCredential = VisibleCredential | PseudonymousCredential

/** draft §5.4.1 Safe AAD component, bound to the MLS PrivateMessage. */
export interface FrankAAD {
  /** HMAC-SHA256 output: exactly 32 bytes. */
  frankingTag: Uint8Array
}

/** draft §5.4.1 GroupContext component identifying the hub signing key. */
export interface FrankingAgentData {
  frankingSignatureKey: Uint8Array
  /** Serialized MLS Credential of the hub's franking agent. */
  credential: Uint8Array
}

export interface ServerFrankingContext {
  senderUri: MimiUserUri
  roomUri: MimiRoomId
  /** UNIX milliseconds as a decimal uint64 string. */
  acceptedTimestamp: string
}

/** Server-generated franking evidence carried with an accepted message. */
export interface Frank {
  serverFrank: Uint8Array
  frankingSignatureCiphersuite: number
  context: ServerFrankingContext
  frankingIntegritySignature: Uint8Array
}

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
  /** MLS credentials for current local leaves, indexed by client identity. */
  memberCredentials: MimiCredential[]
  metadata: RoomMetadata
  /** Hub signing public key and credential, authenticated in MLS GroupContext. */
  frankingAgent?: FrankingAgentData
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

/**
 * Publishes this client's own spare KeyPackages so another member can later
 * add it to a room (`keyMaterial` only ever reads from this store, it never
 * writes to it). The MIMI draft leaves how a provider originally acquires a
 * user's KeyPackages unspecified ("client-server publication is outside the
 * MIMI draft") -- biset fills that gap with its own client-facing route
 * (`/v1/mimi/keypackage/publish`, http.ts), the same way it does for
 * `deliveries/pull`/`watch` (§5.1, PLAN_biset-mimi-server.md). Without this
 * route no client can ever be added to a room: `keyMaterial` would have
 * nothing to return.
 */
export interface KeyPackagePublishRequest {
  version: 1
  credential: MimiCredential
  packages: PublishedKeyPackage[]
  publishedAt: string
  signature: Uint8Array
}

export interface KeyPackagePublishResponse {
  published: number
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
  requester: MimiCredential
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

/** draft §5.7 explicit provider-to-provider consent operation. */
export type MimiConsentOperation = 'cancel' | 'request' | 'grant' | 'revoke'

export interface MimiConsentEntry {
  consentOperation: MimiConsentOperation
  requesterUri: MimiUserUri
  targetUri: MimiUserUri
  roomId?: MimiRoomId
  /** Optional immediately-usable KeyPackages attached to a grant. */
  clientKeyPackages?: PublishedKeyPackage[]
}

export type MimiIdentifierSearchType = 'handle' | 'nick' | 'email' | 'phone' | 'partialName' | 'wholeProfile' | 'oidcStdClaim' | 'vcardField'
export interface MimiIdentifierQueryElement {
  searchType: MimiIdentifierSearchType
  searchValue: string
  fieldName?: string
}
export interface MimiIdentifierRequest { queryElements: MimiIdentifierQueryElement[] }
export type MimiIdentifierQueryCode = 'success' | 'notFound' | 'ambiguous' | 'forbidden' | 'unsupportedField'
export interface MimiIdentifierProfile { stableUri: MimiUserUri; fields: { fieldSource: 'oidcStdClaim' | 'vcardField'; fieldName: string; fieldValue: string }[] }
export interface MimiIdentifierResponse { responseCode: MimiIdentifierQueryCode; foundProfiles: MimiIdentifierProfile[] }

export interface MimiAbusiveMessage { messageContent: Uint8Array; frank: Frank; acceptedTimestamp: string }
export interface MimiAbuseReport { reportingUser?: MimiUserUri; allegedAbuserUri: MimiUserUri; reasonCode: number; note: string; messages: MimiAbusiveMessage[] }

/**
 * draft §5.6 external join (`POST /groupInfo/{roomId}`). Disabled by default
 * (`allowExternalJoin: false`, deployment.ts) since a GroupInfo ratchet tree
 * is plaintext-readable and would disclose every member's real credential to
 * an unauthenticated joiner -- the same reason biset-mls-ds never implemented
 * it for third-party rooms. It is enabled only for a deployment dedicated to
 * Self Group traffic, where the only members are ever the room's own owner's
 * devices, and a new device recovering from its root key has no other device
 * online to add it via an ordinary `add` proposal instead.
 */
export interface GroupInfoRequest {
  version: 1
  protocol: MimiProtocolVersion
  cipherSuite: number
  requester: MimiCredential
  /** HPKE public key the response is encrypted to (draft: groupInfoPublicKey). */
  groupInfoPublicKey: Uint8Array
  requestedAt: string
  signature: Uint8Array
}

export type GroupInfoCode = 'success' | 'notAuthorized' | 'noSuchRoom'

/** The room's stored GroupInfo/ratchet_tree, HPKE-sealed to the requester's
 * groupInfoPublicKey. Pending (uncommitted) proposals are not tracked by
 * this store, so that list is always empty -- a documented simplification,
 * not a wire-format gap. */
export interface GroupInfoRatchetTreeBundle {
  groupInfo: Uint8Array
  ratchetTree?: Uint8Array
}

export interface GroupInfoResponse {
  version: 1
  roomId: MimiRoomId
  status: GroupInfoCode
  cipherSuite?: number
  /** draft's ExternalSender `hub_sender` -- reuses the room's franking
   * signing key as the hub's identity, the same key clients already trust
   * for franking_signature_key (protocol-types.ts's FrankingAgentData). */
  hubSenderSignatureKey?: Uint8Array
  hubSenderCredential?: Uint8Array
  encryptedGroupInfoAndTree?: { kemOutput: Uint8Array; ciphertext: Uint8Array }
  signature?: Uint8Array
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
 * The server-visible state transition carried alongside an MLS handshake.
 * In a future AppSync integration these values are reconstructed directly
 * from the authenticated AppDataUpdate proposal; Phase 0 carries them at the
 * client/provider boundary so the hub can enforce its participant-list gate.
 */
export interface RoomStateUpdate {
  basePolicy?: Uint8Array
  participantList?: ParticipantListData
  memberCredentials?: MimiCredential[]
  metadata?: RoomMetadata
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
  sender: MimiCredential
  epoch: MimiEpoch
  bundle: HandshakeBundle
  stateUpdate?: RoomStateUpdate
  /** Present when this is the initial commit that creates the room. */
  initialState?: Pick<RoomState, 'basePolicy' | 'participantList' | 'memberCredentials' | 'metadata'>
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

export interface SubmitMessageRequest {
  version: 1
  protocol: MimiProtocolVersion
  roomId: MimiRoomId
  sender: MimiCredential
  epoch: MimiEpoch
  appMessage: Uint8Array
  /** Opaque client-generated replay key.  Vault uses this for appendId-equivalent idempotency. */
  deliveryId?: string
  frankAAD: FrankAAD
  frankingSignatureCiphersuite: number
  submittedAt: string
  signature: Uint8Array
}

export interface SubmitMessageResponse {
  status: 'accepted' | 'notAllowed' | 'epochTooOld'
  acceptedTimestamp?: string
  currentEpoch?: MimiEpoch
  frank?: Frank
}

/** Hub-visible manifest for an MLS-encrypted Vault checkpoint.  `transferId`
 * links only opaque client-side chunks; the hub never parses their payload. */
export interface VaultCheckpointManifest {
  coveredSeq: number
  transferId: string
  chunkCount: number
  payloadHash: Uint8Array
}

export interface SubmitVaultCheckpointRequest {
  version: 1
  protocol: MimiProtocolVersion
  roomId: MimiRoomId
  sender: MimiCredential
  epoch: MimiEpoch
  manifest: VaultCheckpointManifest
  submittedAt: string
  signature: Uint8Array
}

export interface SubmitVaultCheckpointResponse {
  status: 'accepted' | 'epochTooOld' | 'conflict'
  acceptedTimestamp?: string
  currentEpoch?: MimiEpoch
}

/** An opaque item delivered from a hub to one of its local clients. */
export type MimiDeliveryKind = 'commit' | 'proposal' | 'welcome' | 'application' | 'vaultCheckpoint'

export interface MimiDeliveryEntry {
  seq: number
  kind: MimiDeliveryKind
  payload: Uint8Array
  epoch: MimiEpoch
  acceptedAt: string
  frank?: Frank
  vaultCheckpoint?: VaultCheckpointManifest
}

export interface DeliveriesPullRequest {
  version: 1
  roomId: MimiRoomId
  requester: MimiCredential
  afterSeq: number
  requestedAt: string
  signature: Uint8Array
}

export interface DeliveriesWatchRequest {
  version: 1
  roomId: MimiRoomId
  requester: MimiCredential
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
