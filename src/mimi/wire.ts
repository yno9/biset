/** JSON + base64url wire boundary for biset-mimi (PLAN §3). */
import { base64urlToBytes, bytesToBase64url } from '../protocol/canonical.ts'
import type {
  ClientKeyMaterial,
  DeliveriesPullRequest,
  DeliveriesWatchRequest,
  DeliveriesWatchToken,
  Frank,
  FrankAAD,
  FrankingAgentData,
  HandshakeBundle,
  KeyMaterialRequest,
  KeyMaterialResponse,
  KeyPackagePublishRequest,
  MimiCredential,
  MimiDeliveryEntry,
  MimiDeliveryKind,
  MimiErrorResponse,
  MimiEpoch,
  MimiProtocolVersion,
  MlsRequiredCapabilities,
  ParticipantListData,
  PseudonymousCredential,
  PublishedKeyPackage,
  RichDescription,
  RoomMetadata,
  RoomState,
  RoomStateUpdate,
  ServerFrankingContext,
  SubmitMessageRequest,
  SubmitMessageResponse,
  UpdateRoomRequest,
  UpdateRoomResponse,
  UserRolePair,
  VisibleCredential,
} from './protocol-types.ts'

export class MimiWireError extends TypeError {}

type JsonRecord = Record<string, unknown>

function record(text: string, name = 'MIMI HTTP body'): JsonRecord {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new MimiWireError(`${name} is not JSON`) }
  return requireRecord(value, name)
}

function requireRecord(value: unknown, name: string): JsonRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MimiWireError(`${name} must be an object`)
  return value as JsonRecord
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new MimiWireError(`${name} must be a non-empty string`)
  return value
}

/** Some draft text fields deliberately permit an empty value. */
function requireText(value: unknown, name: string): string {
  if (typeof value !== 'string') throw new MimiWireError(`${name} must be a string`)
  return value
}

function optionalString(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : requireString(value, name)
}

function requireBinary(value: unknown, name: string): Uint8Array {
  if (typeof value !== 'string') throw new MimiWireError(`${name} must be a base64url string`)
  try { return base64urlToBytes(value) } catch { throw new MimiWireError(`${name} must be a base64url string`) }
}

function optionalBinary(value: unknown, name: string): Uint8Array | undefined {
  return value === undefined ? undefined : requireBinary(value, name)
}

function requireInteger(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new MimiWireError(`${name} must be a non-negative safe integer`)
  return value
}

function requireIntegerArray(value: unknown, name: string): number[] {
  if (!Array.isArray(value)) throw new MimiWireError(`${name} must be an array`)
  return value.map((entry, index) => requireInteger(entry, `${name}[${index}]`))
}

function optionalIntegerArray(value: unknown, name: string): number[] | undefined {
  return value === undefined ? undefined : requireIntegerArray(value, name)
}

function requireStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value)) throw new MimiWireError(`${name} must be an array`)
  return value.map((entry, index) => requireString(entry, `${name}[${index}]`))
}

function optionalStringArray(value: unknown, name: string): string[] | undefined {
  return value === undefined ? undefined : requireStringArray(value, name)
}

function requireBinaryArray(value: unknown, name: string): Uint8Array[] {
  if (!Array.isArray(value)) throw new MimiWireError(`${name} must be an array`)
  return value.map((entry, index) => requireBinary(entry, `${name}[${index}]`))
}

function optionalBinaryArray(value: unknown, name: string): Uint8Array[] | undefined {
  return value === undefined ? undefined : requireBinaryArray(value, name)
}

function requireProtocol(value: unknown, name: string): MimiProtocolVersion {
  if (value !== 'mls10') throw new MimiWireError(`${name} must be mls10`)
  return value
}

function requireEpoch(value: unknown, name: string): MimiEpoch {
  const epoch = requireString(value, name)
  if (!/^(0|[1-9][0-9]{0,19})$/.test(epoch)) throw new MimiWireError(`${name} must be an unsigned 64-bit decimal string`)
  if (BigInt(epoch) > 18_446_744_073_709_551_615n) throw new MimiWireError(`${name} must be an unsigned 64-bit decimal string`)
  return epoch
}

function optional<T>(value: T | undefined, encode: (inner: T) => unknown): unknown {
  return value === undefined ? undefined : encode(value)
}

// ---------------------------------------------------------------- credentials

function visibleCredentialJson(value: VisibleCredential): JsonRecord {
  return {
    kind: value.kind, user: value.user, client: value.client,
    credential: bytesToBase64url(value.credential), signaturePublicKey: bytesToBase64url(value.signaturePublicKey),
  }
}

function decodeVisibleCredential(value: unknown, name: string): VisibleCredential {
  const input = requireRecord(value, name)
  if (input.kind !== 'visible') throw new MimiWireError(`${name}.kind must be visible`)
  return {
    kind: 'visible',
    user: requireString(input.user, `${name}.user`),
    client: requireString(input.client, `${name}.client`),
    credential: requireBinary(input.credential, `${name}.credential`),
    signaturePublicKey: requireBinary(input.signaturePublicKey, `${name}.signaturePublicKey`),
  }
}

function pseudonymousCredentialJson(value: PseudonymousCredential): JsonRecord {
  return {
    kind: value.kind, clientPseudonym: value.clientPseudonym, userPseudonym: value.userPseudonym,
    signaturePublicKey: bytesToBase64url(value.signaturePublicKey),
    identityLinkCiphertext: bytesToBase64url(value.identityLinkCiphertext), signature: bytesToBase64url(value.signature),
  }
}

function decodePseudonymousCredential(value: unknown, name: string): PseudonymousCredential {
  const input = requireRecord(value, name)
  if (input.kind !== 'pseudonymous') throw new MimiWireError(`${name}.kind must be pseudonymous`)
  return {
    kind: 'pseudonymous',
    clientPseudonym: requireString(input.clientPseudonym, `${name}.clientPseudonym`),
    userPseudonym: requireString(input.userPseudonym, `${name}.userPseudonym`),
    signaturePublicKey: requireBinary(input.signaturePublicKey, `${name}.signaturePublicKey`),
    identityLinkCiphertext: requireBinary(input.identityLinkCiphertext, `${name}.identityLinkCiphertext`),
    signature: requireBinary(input.signature, `${name}.signature`),
  }
}

function credentialJson(value: MimiCredential): JsonRecord {
  return value.kind === 'visible' ? visibleCredentialJson(value) : pseudonymousCredentialJson(value)
}

function decodeCredential(value: unknown, name: string): MimiCredential {
  const input = requireRecord(value, name)
  if (input.kind === 'visible') return decodeVisibleCredential(input, name)
  if (input.kind === 'pseudonymous') return decodePseudonymousCredential(input, name)
  throw new MimiWireError(`${name}.kind is invalid`)
}

// ---------------------------------------------------------------- franking

function frankAADJson(value: FrankAAD): JsonRecord { return { frankingTag: bytesToBase64url(value.frankingTag) } }

function decodeFrankAAD(value: unknown, name: string): FrankAAD {
  const input = requireRecord(value, name)
  const frankingTag = requireBinary(input.frankingTag, `${name}.frankingTag`)
  if (frankingTag.length !== 32) throw new MimiWireError(`${name}.frankingTag must be 32 bytes`)
  return { frankingTag }
}

export function encodeFrankAADWire(value: FrankAAD): string {
  if (value.frankingTag.length !== 32) throw new MimiWireError('FrankAAD.frankingTag must be 32 bytes')
  return JSON.stringify(frankAADJson(value))
}

export function decodeFrankAADWire(text: string): FrankAAD { return decodeFrankAAD(record(text, 'FrankAAD'), 'FrankAAD') }

function frankingAgentDataJson(value: FrankingAgentData): JsonRecord {
  return { frankingSignatureKey: bytesToBase64url(value.frankingSignatureKey), credential: bytesToBase64url(value.credential) }
}

function decodeFrankingAgentData(value: unknown, name: string): FrankingAgentData {
  const input = requireRecord(value, name)
  return { frankingSignatureKey: requireBinary(input.frankingSignatureKey, `${name}.frankingSignatureKey`), credential: requireBinary(input.credential, `${name}.credential`) }
}

export function encodeFrankingAgentDataWire(value: FrankingAgentData): string { return JSON.stringify(frankingAgentDataJson(value)) }

export function decodeFrankingAgentDataWire(text: string): FrankingAgentData { return decodeFrankingAgentData(record(text, 'FrankingAgentData'), 'FrankingAgentData') }

function frankingContextJson(value: ServerFrankingContext): JsonRecord {
  return { senderUri: value.senderUri, roomUri: value.roomUri, acceptedTimestamp: value.acceptedTimestamp }
}

function decodeFrankingContext(value: unknown, name: string): ServerFrankingContext {
  const input = requireRecord(value, name)
  return { senderUri: requireString(input.senderUri, `${name}.senderUri`), roomUri: requireString(input.roomUri, `${name}.roomUri`), acceptedTimestamp: requireEpoch(input.acceptedTimestamp, `${name}.acceptedTimestamp`) }
}

export function encodeFrankWire(value: Frank): string {
  if (value.serverFrank.length !== 32) throw new MimiWireError('Frank.serverFrank must be 32 bytes')
  return JSON.stringify({ serverFrank: bytesToBase64url(value.serverFrank), frankingSignatureCiphersuite: value.frankingSignatureCiphersuite, context: frankingContextJson(value.context), frankingIntegritySignature: bytesToBase64url(value.frankingIntegritySignature) })
}

export function decodeFrankWire(text: string): Frank {
  const input = record(text, 'Frank')
  const serverFrank = requireBinary(input.serverFrank, 'Frank.serverFrank')
  if (serverFrank.length !== 32) throw new MimiWireError('Frank.serverFrank must be 32 bytes')
  return { serverFrank, frankingSignatureCiphersuite: requireInteger(input.frankingSignatureCiphersuite, 'Frank.frankingSignatureCiphersuite'), context: decodeFrankingContext(input.context, 'Frank.context'), frankingIntegritySignature: requireBinary(input.frankingIntegritySignature, 'Frank.frankingIntegritySignature') }
}

// --------------------------------------------------------------- room state

function capabilitiesJson(value: MlsRequiredCapabilities): JsonRecord {
  return {
    credentialTypes: optional(value.credentialTypes, entries => [...entries]),
    proposalTypes: optional(value.proposalTypes, entries => [...entries]),
    extensions: optional(value.extensions, entries => [...entries]),
  }
}

function decodeCapabilities(value: unknown, name: string): MlsRequiredCapabilities {
  const input = requireRecord(value, name)
  return {
    credentialTypes: optionalIntegerArray(input.credentialTypes, `${name}.credentialTypes`),
    proposalTypes: optionalIntegerArray(input.proposalTypes, `${name}.proposalTypes`),
    extensions: optionalIntegerArray(input.extensions, `${name}.extensions`),
  }
}

function userRolePairJson(value: UserRolePair): JsonRecord {
  return { user: value.user, roleIndex: value.roleIndex, clientIds: optional(value.clientIds, entries => [...entries]) }
}

function decodeUserRolePair(value: unknown, name: string): UserRolePair {
  const input = requireRecord(value, name)
  return {
    user: requireString(input.user, `${name}.user`),
    roleIndex: requireInteger(input.roleIndex, `${name}.roleIndex`),
    clientIds: optionalStringArray(input.clientIds, `${name}.clientIds`),
  }
}

function participantListJson(value: ParticipantListData): JsonRecord {
  return { participants: value.participants.map(userRolePairJson) }
}

function decodeParticipantList(value: unknown, name: string): ParticipantListData {
  const input = requireRecord(value, name)
  if (!Array.isArray(input.participants)) throw new MimiWireError(`${name}.participants must be an array`)
  return { participants: input.participants.map((entry, index) => decodeUserRolePair(entry, `${name}.participants[${index}]`)) }
}

function richDescriptionJson(value: RichDescription): JsonRecord {
  return { mediaType: value.mediaType, languageTag: value.languageTag, content: value.content }
}

function decodeRichDescription(value: unknown, name: string): RichDescription {
  const input = requireRecord(value, name)
  return {
    mediaType: requireText(input.mediaType, `${name}.mediaType`),
    languageTag: requireText(input.languageTag, `${name}.languageTag`),
    content: requireText(input.content, `${name}.content`),
  }
}

function roomMetadataJson(value: RoomMetadata): JsonRecord {
  return {
    roomUri: value.roomUri, roomName: value.roomName,
    descriptions: optional(value.descriptions, entries => entries.map(richDescriptionJson)),
    roomAvatar: value.roomAvatar, roomSubject: value.roomSubject, roomMood: value.roomMood,
  }
}

function decodeRoomMetadata(value: unknown, name: string): RoomMetadata {
  const input = requireRecord(value, name)
  const descriptions = input.descriptions
  if (descriptions !== undefined && !Array.isArray(descriptions)) throw new MimiWireError(`${name}.descriptions must be an array`)
  return {
    roomUri: requireString(input.roomUri, `${name}.roomUri`),
    roomName: requireString(input.roomName, `${name}.roomName`),
    descriptions: descriptions?.map((entry, index) => decodeRichDescription(entry, `${name}.descriptions[${index}]`)),
    roomAvatar: optionalString(input.roomAvatar, `${name}.roomAvatar`),
    roomSubject: optionalString(input.roomSubject, `${name}.roomSubject`),
    roomMood: optionalString(input.roomMood, `${name}.roomMood`),
  }
}

function roomStateJson(value: RoomState): JsonRecord {
  return {
    roomId: value.roomId, protocol: value.protocol, epoch: value.epoch,
    basePolicy: bytesToBase64url(value.basePolicy), participantList: participantListJson(value.participantList), memberCredentials: value.memberCredentials.map(credentialJson), metadata: roomMetadataJson(value.metadata),
    groupInfo: optional(value.groupInfo, bytesToBase64url), ratchetTree: optional(value.ratchetTree, bytesToBase64url),
    createdAt: value.createdAt, updatedAt: value.updatedAt,
  }
}

export function encodeRoomStateWire(value: RoomState): string { return JSON.stringify(roomStateJson(value)) }

export function decodeRoomStateWire(text: string): RoomState {
  const input = record(text, 'RoomState')
  return {
    roomId: requireString(input.roomId, 'RoomState.roomId'), protocol: requireProtocol(input.protocol, 'RoomState.protocol'), epoch: requireEpoch(input.epoch, 'RoomState.epoch'),
    basePolicy: requireBinary(input.basePolicy, 'RoomState.basePolicy'),
    participantList: decodeParticipantList(input.participantList, 'RoomState.participantList'),
    memberCredentials: (() => { if (!Array.isArray(input.memberCredentials)) throw new MimiWireError('RoomState.memberCredentials must be an array'); return input.memberCredentials.map((entry, index) => decodeCredential(entry, `RoomState.memberCredentials[${index}]`)) })(),
    metadata: decodeRoomMetadata(input.metadata, 'RoomState.metadata'),
    groupInfo: optionalBinary(input.groupInfo, 'RoomState.groupInfo'), ratchetTree: optionalBinary(input.ratchetTree, 'RoomState.ratchetTree'),
    createdAt: requireString(input.createdAt, 'RoomState.createdAt'), updatedAt: requireString(input.updatedAt, 'RoomState.updatedAt'),
  }
}

// ------------------------------------------------------------ key material

function publishedKeyPackageJson(value: PublishedKeyPackage): JsonRecord {
  return {
    reference: bytesToBase64url(value.reference), user: value.user, client: value.client, keyPackage: bytesToBase64url(value.keyPackage),
    capabilities: optional(value.capabilities, capabilitiesJson), publishedAt: value.publishedAt, expiresAt: value.expiresAt, sourceProvider: value.sourceProvider,
  }
}

function decodePublishedKeyPackage(value: unknown, name: string): PublishedKeyPackage {
  const input = requireRecord(value, name)
  return {
    reference: requireBinary(input.reference, `${name}.reference`), user: requireString(input.user, `${name}.user`), client: requireString(input.client, `${name}.client`),
    keyPackage: requireBinary(input.keyPackage, `${name}.keyPackage`),
    capabilities: input.capabilities === undefined ? undefined : decodeCapabilities(input.capabilities, `${name}.capabilities`),
    publishedAt: requireString(input.publishedAt, `${name}.publishedAt`), expiresAt: optionalString(input.expiresAt, `${name}.expiresAt`), sourceProvider: optionalString(input.sourceProvider, `${name}.sourceProvider`),
  }
}

export function encodeKeyPackagePublishWire(value: KeyPackagePublishRequest): string {
  return JSON.stringify({ version: value.version, credential: credentialJson(value.credential), packages: value.packages.map(publishedKeyPackageJson), publishedAt: value.publishedAt, signature: bytesToBase64url(value.signature) })
}

export function decodeKeyPackagePublishWire(text: string): KeyPackagePublishRequest {
  const input = record(text)
  if (input.version !== 1) throw new MimiWireError('KeyPackagePublishRequest.version must be 1')
  if (!Array.isArray(input.packages)) throw new MimiWireError('KeyPackagePublishRequest.packages must be an array')
  return {
    version: 1, credential: decodeCredential(input.credential, 'KeyPackagePublishRequest.credential'),
    packages: input.packages.map((entry, index) => decodePublishedKeyPackage(entry, `KeyPackagePublishRequest.packages[${index}]`)),
    publishedAt: requireString(input.publishedAt, 'KeyPackagePublishRequest.publishedAt'), signature: requireBinary(input.signature, 'KeyPackagePublishRequest.signature'),
  }
}

export function encodeKeyMaterialRequestWire(value: KeyMaterialRequest): string {
  return JSON.stringify({
    version: value.version, protocol: value.protocol, requestingUser: value.requestingUser, targetUser: value.targetUser, roomId: value.roomId,
    acceptableCiphersuites: value.acceptableCiphersuites, requiredCapabilities: capabilitiesJson(value.requiredCapabilities), requester: credentialJson(value.requester), signature: bytesToBase64url(value.signature),
  })
}

export function decodeKeyMaterialRequestWire(text: string): KeyMaterialRequest {
  const input = record(text)
  if (input.version !== 1) throw new MimiWireError('KeyMaterialRequest.version must be 1')
  return {
    version: 1, protocol: requireProtocol(input.protocol, 'KeyMaterialRequest.protocol'),
    requestingUser: requireString(input.requestingUser, 'KeyMaterialRequest.requestingUser'), targetUser: requireString(input.targetUser, 'KeyMaterialRequest.targetUser'), roomId: requireString(input.roomId, 'KeyMaterialRequest.roomId'),
    acceptableCiphersuites: requireIntegerArray(input.acceptableCiphersuites, 'KeyMaterialRequest.acceptableCiphersuites'),
    requiredCapabilities: decodeCapabilities(input.requiredCapabilities, 'KeyMaterialRequest.requiredCapabilities'), requester: decodeCredential(input.requester, 'KeyMaterialRequest.requester'),
    signature: requireBinary(input.signature, 'KeyMaterialRequest.signature'),
  }
}

function clientKeyMaterialJson(value: ClientKeyMaterial): JsonRecord {
  return { client: value.client, status: value.status, keyPackage: optional(value.keyPackage, bytesToBase64url), capabilities: optional(value.capabilities, capabilitiesJson) }
}

function decodeClientKeyMaterial(value: unknown, name: string): ClientKeyMaterial {
  const input = requireRecord(value, name)
  const status = input.status
  if (status !== 'success' && status !== 'keyMaterialExhausted' && status !== 'nothingCompatible') throw new MimiWireError(`${name}.status is invalid`)
  return { client: requireString(input.client, `${name}.client`), status, keyPackage: optionalBinary(input.keyPackage, `${name}.keyPackage`), capabilities: input.capabilities === undefined ? undefined : decodeCapabilities(input.capabilities, `${name}.capabilities`) }
}

const KEY_MATERIAL_USER_STATUSES = new Set(['success', 'partialSuccess', 'incompatibleProtocol', 'noCompatibleMaterial', 'userUnknown', 'noConsent', 'noConsentForThisRoom', 'userDeleted'])

export function encodeKeyMaterialResponseWire(value: KeyMaterialResponse): string {
  return JSON.stringify({ protocol: value.protocol, user: value.user, status: value.status, clients: value.clients.map(clientKeyMaterialJson) })
}

export function decodeKeyMaterialResponseWire(text: string): KeyMaterialResponse {
  const input = record(text)
  if (typeof input.status !== 'string' || !KEY_MATERIAL_USER_STATUSES.has(input.status)) throw new MimiWireError('KeyMaterialResponse.status is invalid')
  if (!Array.isArray(input.clients)) throw new MimiWireError('KeyMaterialResponse.clients must be an array')
  return { protocol: requireProtocol(input.protocol, 'KeyMaterialResponse.protocol'), user: requireString(input.user, 'KeyMaterialResponse.user'), status: input.status as KeyMaterialResponse['status'], clients: input.clients.map((entry, index) => decodeClientKeyMaterial(entry, `KeyMaterialResponse.clients[${index}]`)) }
}

// ------------------------------------------------------------------ update

function handshakeBundleJson(value: HandshakeBundle): JsonRecord {
  return {
    kind: value.kind, proposalOrCommit: bytesToBase64url(value.proposalOrCommit), moreProposals: optional(value.moreProposals, entries => entries.map(bytesToBase64url)),
    welcome: optional(value.welcome, bytesToBase64url), groupInfo: optional(value.groupInfo, bytesToBase64url), ratchetTree: optional(value.ratchetTree, bytesToBase64url),
  }
}

function decodeHandshakeBundle(value: unknown, name: string): HandshakeBundle {
  const input = requireRecord(value, name)
  if (input.kind !== 'commit' && input.kind !== 'proposal') throw new MimiWireError(`${name}.kind is invalid`)
  return {
    kind: input.kind, proposalOrCommit: requireBinary(input.proposalOrCommit, `${name}.proposalOrCommit`),
    moreProposals: optionalBinaryArray(input.moreProposals, `${name}.moreProposals`), welcome: optionalBinary(input.welcome, `${name}.welcome`),
    groupInfo: optionalBinary(input.groupInfo, `${name}.groupInfo`), ratchetTree: optionalBinary(input.ratchetTree, `${name}.ratchetTree`),
  }
}

function roomStateUpdateJson(value: RoomStateUpdate): JsonRecord {
  return {
    basePolicy: optional(value.basePolicy, bytesToBase64url),
    participantList: optional(value.participantList, participantListJson),
    memberCredentials: optional(value.memberCredentials, entries => entries.map(credentialJson)),
    metadata: optional(value.metadata, roomMetadataJson),
  }
}

function decodeRoomStateUpdate(value: unknown, name: string): RoomStateUpdate {
  const input = requireRecord(value, name)
  return {
    basePolicy: optionalBinary(input.basePolicy, `${name}.basePolicy`),
    participantList: input.participantList === undefined ? undefined : decodeParticipantList(input.participantList, `${name}.participantList`),
    memberCredentials: input.memberCredentials === undefined ? undefined : (() => { if (!Array.isArray(input.memberCredentials)) throw new MimiWireError(`${name}.memberCredentials must be an array`); return input.memberCredentials.map((entry, index) => decodeCredential(entry, `${name}.memberCredentials[${index}]`)) })(),
    metadata: input.metadata === undefined ? undefined : decodeRoomMetadata(input.metadata, `${name}.metadata`),
  }
}

export function encodeUpdateRoomRequestWire(value: UpdateRoomRequest): string {
  return JSON.stringify({
    version: value.version, protocol: value.protocol, roomId: value.roomId, sender: credentialJson(value.sender), epoch: value.epoch, bundle: handshakeBundleJson(value.bundle),
    stateUpdate: optional(value.stateUpdate, roomStateUpdateJson),
    initialState: value.initialState === undefined ? undefined : { basePolicy: bytesToBase64url(value.initialState.basePolicy), participantList: participantListJson(value.initialState.participantList), memberCredentials: value.initialState.memberCredentials.map(credentialJson), metadata: roomMetadataJson(value.initialState.metadata) },
    submittedAt: value.submittedAt, signature: bytesToBase64url(value.signature),
  })
}

export function decodeUpdateRoomRequestWire(text: string): UpdateRoomRequest {
  const input = record(text)
  if (input.version !== 1) throw new MimiWireError('UpdateRoomRequest.version must be 1')
  const initialStateInput = input.initialState === undefined ? undefined : requireRecord(input.initialState, 'UpdateRoomRequest.initialState')
  return {
    version: 1, protocol: requireProtocol(input.protocol, 'UpdateRoomRequest.protocol'), roomId: requireString(input.roomId, 'UpdateRoomRequest.roomId'),
    sender: decodeCredential(input.sender, 'UpdateRoomRequest.sender'), epoch: requireEpoch(input.epoch, 'UpdateRoomRequest.epoch'), bundle: decodeHandshakeBundle(input.bundle, 'UpdateRoomRequest.bundle'),
    stateUpdate: input.stateUpdate === undefined ? undefined : decodeRoomStateUpdate(input.stateUpdate, 'UpdateRoomRequest.stateUpdate'),
    initialState: initialStateInput === undefined ? undefined : {
      basePolicy: requireBinary(initialStateInput.basePolicy, 'UpdateRoomRequest.initialState.basePolicy'), participantList: decodeParticipantList(initialStateInput.participantList, 'UpdateRoomRequest.initialState.participantList'),
      memberCredentials: (() => { if (!Array.isArray(initialStateInput.memberCredentials)) throw new MimiWireError('UpdateRoomRequest.initialState.memberCredentials must be an array'); return initialStateInput.memberCredentials.map((entry, index) => decodeCredential(entry, `UpdateRoomRequest.initialState.memberCredentials[${index}]`)) })(),
      metadata: decodeRoomMetadata(initialStateInput.metadata, 'UpdateRoomRequest.initialState.metadata'),
    },
    submittedAt: requireString(input.submittedAt, 'UpdateRoomRequest.submittedAt'), signature: requireBinary(input.signature, 'UpdateRoomRequest.signature'),
  }
}

export function encodeUpdateRoomResponseWire(value: UpdateRoomResponse): string {
  return JSON.stringify({ status: value.status, acceptedTimestamp: value.acceptedTimestamp, currentEpoch: value.currentEpoch, invalidProposals: optional(value.invalidProposals, entries => entries.map(bytesToBase64url)), errorDescription: value.errorDescription })
}

export function decodeUpdateRoomResponseWire(text: string): UpdateRoomResponse {
  const input = record(text)
  if (input.status !== 'success' && input.status !== 'wrongEpoch' && input.status !== 'notAllowed' && input.status !== 'invalidProposal') throw new MimiWireError('UpdateRoomResponse.status is invalid')
  return { status: input.status, acceptedTimestamp: optionalString(input.acceptedTimestamp, 'UpdateRoomResponse.acceptedTimestamp'), currentEpoch: input.currentEpoch === undefined ? undefined : requireEpoch(input.currentEpoch, 'UpdateRoomResponse.currentEpoch'), invalidProposals: optionalBinaryArray(input.invalidProposals, 'UpdateRoomResponse.invalidProposals'), errorDescription: optionalString(input.errorDescription, 'UpdateRoomResponse.errorDescription') }
}

export function encodeSubmitMessageRequestWire(value: SubmitMessageRequest): string {
  return JSON.stringify({ version: value.version, protocol: value.protocol, roomId: value.roomId, sender: credentialJson(value.sender), epoch: value.epoch, appMessage: bytesToBase64url(value.appMessage), frankAAD: frankAADJson(value.frankAAD), frankingSignatureCiphersuite: value.frankingSignatureCiphersuite, submittedAt: value.submittedAt, signature: bytesToBase64url(value.signature) })
}
export function decodeSubmitMessageRequestWire(text: string): SubmitMessageRequest {
  const input = record(text)
  if (input.version !== 1) throw new MimiWireError('SubmitMessageRequest.version must be 1')
  return { version: 1, protocol: requireProtocol(input.protocol, 'SubmitMessageRequest.protocol'), roomId: requireString(input.roomId, 'SubmitMessageRequest.roomId'), sender: decodeCredential(input.sender, 'SubmitMessageRequest.sender'), epoch: requireEpoch(input.epoch, 'SubmitMessageRequest.epoch'), appMessage: requireBinary(input.appMessage, 'SubmitMessageRequest.appMessage'), frankAAD: decodeFrankAAD(input.frankAAD, 'SubmitMessageRequest.frankAAD'), frankingSignatureCiphersuite: requireInteger(input.frankingSignatureCiphersuite, 'SubmitMessageRequest.frankingSignatureCiphersuite'), submittedAt: requireString(input.submittedAt, 'SubmitMessageRequest.submittedAt'), signature: requireBinary(input.signature, 'SubmitMessageRequest.signature') }
}
export function encodeSubmitMessageResponseWire(value: SubmitMessageResponse): string { return JSON.stringify({ status: value.status, acceptedTimestamp: value.acceptedTimestamp, currentEpoch: value.currentEpoch, frank: value.frank === undefined ? undefined : JSON.parse(encodeFrankWire(value.frank)) }) }

export function decodeSubmitMessageResponseWire(text: string): SubmitMessageResponse {
  const input = record(text)
  if (input.status !== 'accepted' && input.status !== 'notAllowed' && input.status !== 'epochTooOld') throw new MimiWireError('SubmitMessageResponse.status is invalid')
  return { status: input.status, acceptedTimestamp: optionalString(input.acceptedTimestamp, 'SubmitMessageResponse.acceptedTimestamp'), currentEpoch: input.currentEpoch === undefined ? undefined : requireEpoch(input.currentEpoch, 'SubmitMessageResponse.currentEpoch'), frank: input.frank === undefined ? undefined : decodeFrankWire(JSON.stringify(input.frank)) }
}

// --------------------------------------------------------------- deliveries

function deliveriesRequesterJson(value: DeliveriesPullRequest | DeliveriesWatchRequest): JsonRecord {
  return { version: value.version, roomId: value.roomId, requester: credentialJson(value.requester), requestedAt: value.requestedAt, signature: bytesToBase64url(value.signature) }
}

export function encodeDeliveriesPullRequestWire(value: DeliveriesPullRequest): string {
  return JSON.stringify({ ...deliveriesRequesterJson(value), afterSeq: value.afterSeq })
}

export function decodeDeliveriesPullRequestWire(text: string): DeliveriesPullRequest {
  const input = record(text)
  if (input.version !== 1) throw new MimiWireError('DeliveriesPullRequest.version must be 1')
  return { version: 1, roomId: requireString(input.roomId, 'DeliveriesPullRequest.roomId'), requester: decodeCredential(input.requester, 'DeliveriesPullRequest.requester'), afterSeq: requireInteger(input.afterSeq, 'DeliveriesPullRequest.afterSeq'), requestedAt: requireString(input.requestedAt, 'DeliveriesPullRequest.requestedAt'), signature: requireBinary(input.signature, 'DeliveriesPullRequest.signature') }
}

export function encodeDeliveriesWatchRequestWire(value: DeliveriesWatchRequest): string { return JSON.stringify(deliveriesRequesterJson(value)) }

export function decodeDeliveriesWatchRequestWire(text: string): DeliveriesWatchRequest {
  const input = record(text)
  if (input.version !== 1) throw new MimiWireError('DeliveriesWatchRequest.version must be 1')
  return { version: 1, roomId: requireString(input.roomId, 'DeliveriesWatchRequest.roomId'), requester: decodeCredential(input.requester, 'DeliveriesWatchRequest.requester'), requestedAt: requireString(input.requestedAt, 'DeliveriesWatchRequest.requestedAt'), signature: requireBinary(input.signature, 'DeliveriesWatchRequest.signature') }
}

function deliveryEntryJson(value: MimiDeliveryEntry): JsonRecord {
  return { seq: value.seq, kind: value.kind, payload: bytesToBase64url(value.payload), epoch: value.epoch, acceptedAt: value.acceptedAt, frank: value.frank === undefined ? undefined : JSON.parse(encodeFrankWire(value.frank)) }
}

function decodeDeliveryEntry(value: unknown, name: string): MimiDeliveryEntry {
  const input = requireRecord(value, name)
  const kind = input.kind
  if (kind !== 'commit' && kind !== 'proposal' && kind !== 'welcome' && kind !== 'application') throw new MimiWireError(`${name}.kind is invalid`)
  return { seq: requireInteger(input.seq, `${name}.seq`), kind: kind as MimiDeliveryKind, payload: requireBinary(input.payload, `${name}.payload`), epoch: requireEpoch(input.epoch, `${name}.epoch`), acceptedAt: requireString(input.acceptedAt, `${name}.acceptedAt`), frank: input.frank === undefined ? undefined : decodeFrankWire(JSON.stringify(input.frank)) }
}

export function encodeDeliveriesWire(entries: MimiDeliveryEntry[]): string { return JSON.stringify({ entries: entries.map(deliveryEntryJson) }) }

export function decodeDeliveriesWire(text: string): MimiDeliveryEntry[] {
  const input = record(text)
  if (!Array.isArray(input.entries)) throw new MimiWireError('deliveries.entries must be an array')
  return input.entries.map((entry, index) => decodeDeliveryEntry(entry, `deliveries.entries[${index}]`))
}

export function deliveryEntryWireJson(entry: MimiDeliveryEntry): JsonRecord { return deliveryEntryJson(entry) }

export function encodeDeliveriesWatchTokenWire(value: DeliveriesWatchToken): string { return JSON.stringify(value) }

export function decodeDeliveriesWatchTokenWire(text: string): DeliveriesWatchToken {
  const input = record(text)
  return { token: requireString(input.token, 'watch token'), expiresAt: requireString(input.expiresAt, 'watch expiry') }
}

export function encodeMimiErrorWire(value: MimiErrorResponse): string { return JSON.stringify(value) }

export function decodeMimiErrorWire(text: string): MimiErrorResponse {
  const input = record(text)
  const error = input.error
  if (error !== 'bad-request' && error !== 'unauthorized' && error !== 'not-found' && error !== 'conflict' && error !== 'not-allowed' && error !== 'internal-error') throw new MimiWireError('error response code is invalid')
  return { error, message: requireString(input.message, 'error response message') }
}
