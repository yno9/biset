/**
 * Authentication and authorization at biset-mimi's client-to-hub boundary.
 * MIMI intentionally does not standardize this provider-internal hop; Phase
 * 0 uses a client's MLS credential signature key with domain-separated
 * canonical request bytes.  The store additionally pins a sender's key to
 * the credential already recorded in the room, so a self-asserted request
 * credential cannot replace an existing member's signing key.
 */
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url, canonicalBytes, equalBytes } from '../protocol/canonical.ts'
import type { CanonicalValue } from '../protocol/canonical.ts'
import type {
  DeliveriesPullRequest,
  DeliveriesWatchRequest,
  GroupInfoRequest,
  GroupInfoResponse,
  KeyMaterialRequest,
  KeyMaterialResponse,
  KeyPackagePublishRequest,
  MimiCredential,
  MimiRoomId,
  MlsRequiredCapabilities,
  RoomStateUpdate,
  SubmitMessageRequest,
  SubmitVaultCheckpointRequest,
  UpdateRoomRequest,
  VisibleCredential,
} from './protocol-types.ts'
import type { SqliteMimiStore } from './store.ts'
import { encodeCredential } from '../mls/vendor/credential.ts'

export interface MimiSignatureVerifier {
  verify(credential: MimiCredential, bytes: Uint8Array, signature: Uint8Array): Promise<boolean>
}

export class Ed25519MimiSignatureVerifier implements MimiSignatureVerifier {
  async verify(credential: MimiCredential, bytes: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return signature.length === 64 && credential.signaturePublicKey.length === 32 && ed25519.verify(signature, bytes, credential.signaturePublicKey)
  }
}

export function keyMaterialSigningBytes(value: Omit<KeyMaterialRequest, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mimi-key-material/v1', version: value.version, protocol: value.protocol,
    requestingUser: value.requestingUser, targetUser: value.targetUser, roomId: value.roomId,
    acceptableCiphersuites: value.acceptableCiphersuites, requiredCapabilities: capabilitiesValue(value.requiredCapabilities), requester: credentialValue(value.requester),
  })
}

export function keyPackagePublishSigningBytes(value: Omit<KeyPackagePublishRequest, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mimi-key-package-publish/v1', version: value.version, credential: credentialValue(value.credential),
    packages: value.packages.map(item => ({
      reference: bytesToBase64url(item.reference), user: item.user, client: item.client, keyPackage: bytesToBase64url(item.keyPackage),
      ...(item.capabilities === undefined ? {} : { capabilities: capabilitiesValue(item.capabilities) }), publishedAt: item.publishedAt,
      ...(item.expiresAt === undefined ? {} : { expiresAt: item.expiresAt }), ...(item.sourceProvider === undefined ? {} : { sourceProvider: item.sourceProvider }),
    })),
    publishedAt: value.publishedAt,
  })
}

export function updateRoomSigningBytes(value: Omit<UpdateRoomRequest, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mimi-update-room/v1', version: value.version, protocol: value.protocol, roomId: value.roomId,
    sender: credentialValue(value.sender), epoch: value.epoch, bundle: handshakeBundleValue(value.bundle),
    ...(value.stateUpdate === undefined ? {} : { stateUpdate: roomStateUpdateValue(value.stateUpdate) }),
    ...(value.initialState === undefined ? {} : { initialState: {
      basePolicy: bytesToBase64url(value.initialState.basePolicy), participantList: participantListValue(value.initialState.participantList),
      memberCredentials: value.initialState.memberCredentials.map(credentialValue), metadata: roomMetadataValue(value.initialState.metadata),
    } }),
    submittedAt: value.submittedAt,
  })
}

export function deliveriesPullSigningBytes(value: Omit<DeliveriesPullRequest, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mimi-deliveries-pull/v1', version: value.version, roomId: value.roomId, requester: credentialValue(value.requester), afterSeq: value.afterSeq, requestedAt: value.requestedAt,
  })
}

export function deliveriesWatchSigningBytes(value: Omit<DeliveriesWatchRequest, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mimi-deliveries-watch/v1', version: value.version, roomId: value.roomId, requester: credentialValue(value.requester), requestedAt: value.requestedAt,
  })
}

export function submitMessageSigningBytes(value: Omit<SubmitMessageRequest, 'signature'>): Uint8Array {
  return canonicalBytes({ label: 'biset/mimi-submit-message/v1', version: value.version, protocol: value.protocol, roomId: value.roomId, sender: credentialValue(value.sender), epoch: value.epoch, appMessage: bytesToBase64url(value.appMessage), ...(value.deliveryId === undefined ? {} : { deliveryId: value.deliveryId }), frankingTag: bytesToBase64url(value.frankAAD.frankingTag), frankingSignatureCiphersuite: value.frankingSignatureCiphersuite, submittedAt: value.submittedAt })
}

export function submitVaultCheckpointSigningBytes(value: Omit<SubmitVaultCheckpointRequest, 'signature'>): Uint8Array {
  return canonicalBytes({ label: 'biset/mimi-vault-checkpoint/v1', version: value.version, protocol: value.protocol, roomId: value.roomId, sender: credentialValue(value.sender), epoch: value.epoch, manifest: { coveredSeq: value.manifest.coveredSeq, transferId: value.manifest.transferId, chunkCount: value.manifest.chunkCount, payloadHash: bytesToBase64url(value.manifest.payloadHash) }, submittedAt: value.submittedAt })
}

export async function authorizeUpdate(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: UpdateRoomRequest): Promise<boolean> {
  if (!(await verifier.verify(value.sender, updateRoomSigningBytes(value), value.signature))) return false
  const room = store.room(value.roomId)
  // An initial update is the one self-authenticated entry point.  Its signer
  // must be in `initialState`; the store enforces that invariant.  Once a
  // room exists, pin both user/client and public key to its persisted leaf.
  return room === undefined ? value.initialState !== undefined : credentialMatchesRoom(store, value.roomId, value.sender)
}

/** Self-room external join: a freshly restored device has a new MLS
 * credential, so exact client-key matching cannot precede its first commit.
 * This is intentionally narrower than ordinary update authorization and the
 * HTTP layer enables it only for an allowExternalJoin deployment. */
export async function authorizeExternalJoinUpdate(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: UpdateRoomRequest): Promise<boolean> {
  if (value.initialState !== undefined || value.bundle.kind !== 'commit' || value.sender.kind !== 'visible') return false
  return (await verifier.verify(value.sender, updateRoomSigningBytes(value), value.signature)) && userIsRoomParticipant(store.room(value.roomId), value.sender.user)
}

export async function authorizeKeyMaterial(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: KeyMaterialRequest): Promise<boolean> {
  if (value.requestingUser !== credentialUser(value.requester)) return false
  if (!(await verifier.verify(value.requester, keyMaterialSigningBytes(value), value.signature))) return false
  const room = store.room(value.roomId)
  return room !== undefined && credentialMatchesRoom(store, value.roomId, value.requester)
}

export async function authorizeKeyPackagePublish(verifier: MimiSignatureVerifier, value: KeyPackagePublishRequest): Promise<boolean> {
  return verifier.verify(value.credential, keyPackagePublishSigningBytes(value), value.signature)
}

export async function authorizeDeliveriesPull(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: DeliveriesPullRequest): Promise<boolean> {
  return (await verifier.verify(value.requester, deliveriesPullSigningBytes(value), value.signature)) && credentialMatchesRoom(store, value.roomId, value.requester)
}

export async function authorizeDeliveriesWatch(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: DeliveriesWatchRequest): Promise<boolean> {
  return (await verifier.verify(value.requester, deliveriesWatchSigningBytes(value), value.signature)) && credentialMatchesRoom(store, value.roomId, value.requester)
}

export async function authorizeSubmitMessage(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: SubmitMessageRequest): Promise<boolean> {
  return (await verifier.verify(value.sender, submitMessageSigningBytes(value), value.signature)) && credentialMatchesRoom(store, value.roomId, value.sender)
}
export async function authorizeSubmitVaultCheckpoint(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: SubmitVaultCheckpointRequest): Promise<boolean> {
  return (await verifier.verify(value.sender, submitVaultCheckpointSigningBytes(value), value.signature)) && credentialMatchesRoom(store, value.roomId, value.sender)
}

export function groupInfoRequestSigningBytes(value: Omit<GroupInfoRequest, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mimi-group-info-request/v1', version: value.version, protocol: value.protocol, cipherSuite: value.cipherSuite,
    requester: credentialValue(value.requester), groupInfoPublicKey: bytesToBase64url(value.groupInfoPublicKey), requestedAt: value.requestedAt,
  })
}

export function groupInfoResponseSigningBytes(value: Omit<GroupInfoResponse, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mimi-group-info-response/v1', version: value.version, roomId: value.roomId, status: value.status,
    ...(value.cipherSuite === undefined ? {} : { cipherSuite: value.cipherSuite }),
    ...(value.hubSenderSignatureKey === undefined ? {} : { hubSenderSignatureKey: bytesToBase64url(value.hubSenderSignatureKey) }),
    ...(value.hubSenderCredential === undefined ? {} : { hubSenderCredential: bytesToBase64url(value.hubSenderCredential) }),
    ...(value.encryptedGroupInfoAndTree === undefined ? {} : { encryptedGroupInfoAndTree: { kemOutput: bytesToBase64url(value.encryptedGroupInfoAndTree.kemOutput), ciphertext: bytesToBase64url(value.encryptedGroupInfoAndTree.ciphertext) } }),
  })
}

/** Signature proves possession; the room membership check that follows is by
 * stable user URI, not by exact credential -- the whole point of external
 * join is that the requester's device/credential is brand new and has never
 * been seen by this room before (§18, PLAN_biset-mimi-server.md). */
export async function authorizeGroupInfoRequest(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: GroupInfoRequest): Promise<boolean> {
  if (!(await verifier.verify(value.requester, groupInfoRequestSigningBytes(value), value.signature))) return false
  return value.requester.kind === 'visible'
}

export function userIsRoomParticipant(room: ReturnType<SqliteMimiStore['room']>, user: string): boolean {
  return room !== undefined && room.participantList.participants.some(participant => participant.user === user)
}

/** Turns the store's single-use KeyPackage take into draft §5.2 status data. */
export function keyMaterialResponse(targetUser: string, packages: ReturnType<SqliteMimiStore['takeKeyPackages']>): KeyMaterialResponse {
  if (packages.length === 0) return { protocol: 'mls10', user: targetUser, status: 'noCompatibleMaterial', clients: [] }
  return {
    protocol: 'mls10', user: targetUser, status: 'success',
    clients: packages.map(item => ({ client: item.client, status: 'success', keyPackage: item.keyPackage, capabilities: item.capabilities })),
  }
}

/**
 * Two independent ways a request's claimed credential can be trusted, tried
 * in order -- either is sufficient:
 *
 * 1. The original biset sidecar check: exact match against `memberCredentials`
 *    (populated from a client-signed `initialState`/`stateUpdate` sidecar,
 *    cross-checked at commit time against real `add` proposals for anyone
 *    newly added -- store.ts's `assertAddedCredentialsBackedByMls`).
 * 2. (PLAN_biset-mimi-server.md §21) If the room has tracked MLS public
 *    state (mlsPublicState -- present once a client has supplied a
 *    verifiable GroupInfo), the claimed (credential, signaturePublicKey)
 *    pair matching some real leaf in the *actual tracked ratchet tree*, for
 *    a user currently in the participant list. This is the spec's own
 *    model (§9: authenticate via the MLS PublicMessage/credential
 *    machinery itself) and needs no sidecar at all -- it is why this also
 *    closes PLAN §20.2's federation gaps (a federated room's own local
 *    participant was never going to have a memberCredentials sidecar
 *    entry, since nothing client-signed ever proposed one).
 *
 * Kept as an OR, not a replacement: rooms with no tracked state (still the
 * common case) behave exactly as before this existed.
 */
function credentialMatchesRoom(store: SqliteMimiStore, roomId: MimiRoomId, signer: MimiCredential): boolean {
  const room = store.room(roomId)
  const user = credentialUser(signer)
  if (!room || !room.participantList.participants.some(participant => participant.user === user)) return false
  if (room.memberCredentials.some(credential => credential.kind === signer.kind && equalBytes(credential.signaturePublicKey, signer.signaturePublicKey) && (credential.kind === 'visible' && signer.kind === 'visible' ? credential.client === signer.client : credential.kind === 'pseudonymous' && signer.kind === 'pseudonymous' ? credential.clientPseudonym === signer.clientPseudonym : false))) return true
  if (signer.kind !== 'visible') return false
  const tracked = store.mlsPublicState(roomId)
  if (!tracked) return false
  return tracked.ratchetTree.some(node => node?.nodeType === 'leaf' && equalBytes(node.leaf.signaturePublicKey, signer.signaturePublicKey) && equalBytes(encodeCredential(node.leaf.credential), signer.credential))
}

function credentialUser(credential: MimiCredential): string { return credential.kind === 'visible' ? credential.user : credential.userPseudonym }

function visibleCredentialValue(value: VisibleCredential): CanonicalValue {
  return { kind: value.kind, user: value.user, client: value.client, credential: bytesToBase64url(value.credential), signaturePublicKey: bytesToBase64url(value.signaturePublicKey) }
}

function credentialValue(value: MimiCredential): CanonicalValue {
  if (value.kind === 'visible') return visibleCredentialValue(value)
  return {
    kind: value.kind, clientPseudonym: value.clientPseudonym, userPseudonym: value.userPseudonym,
    signaturePublicKey: bytesToBase64url(value.signaturePublicKey), identityLinkCiphertext: bytesToBase64url(value.identityLinkCiphertext),
  }
}

function capabilitiesValue(value: MlsRequiredCapabilities): CanonicalValue {
  return {
    ...(value.credentialTypes === undefined ? {} : { credentialTypes: value.credentialTypes }),
    ...(value.proposalTypes === undefined ? {} : { proposalTypes: value.proposalTypes }),
    ...(value.extensions === undefined ? {} : { extensions: value.extensions }),
  }
}

function participantListValue(value: { participants: { user: string; roleIndex: number; clientIds?: string[] }[] }): CanonicalValue {
  return { participants: value.participants.map(participant => ({ user: participant.user, roleIndex: participant.roleIndex, ...(participant.clientIds === undefined ? {} : { clientIds: participant.clientIds }) })) }
}

function roomMetadataValue(value: { roomUri: string; roomName: string; descriptions?: { mediaType: string; languageTag: string; content: string }[]; roomAvatar?: string; roomSubject?: string; roomMood?: string }): CanonicalValue {
  return {
    roomUri: value.roomUri, roomName: value.roomName,
    ...(value.descriptions === undefined ? {} : { descriptions: value.descriptions.map(description => ({ mediaType: description.mediaType, languageTag: description.languageTag, content: description.content })) }),
    ...(value.roomAvatar === undefined ? {} : { roomAvatar: value.roomAvatar }), ...(value.roomSubject === undefined ? {} : { roomSubject: value.roomSubject }), ...(value.roomMood === undefined ? {} : { roomMood: value.roomMood }),
  }
}

function roomStateUpdateValue(value: RoomStateUpdate): CanonicalValue {
  return {
    ...(value.basePolicy === undefined ? {} : { basePolicy: bytesToBase64url(value.basePolicy) }),
    ...(value.participantList === undefined ? {} : { participantList: participantListValue(value.participantList) }),
    ...(value.memberCredentials === undefined ? {} : { memberCredentials: value.memberCredentials.map(credentialValue) }),
    ...(value.metadata === undefined ? {} : { metadata: roomMetadataValue(value.metadata) }),
  }
}

function handshakeBundleValue(value: UpdateRoomRequest['bundle']): CanonicalValue {
  return {
    kind: value.kind, proposalOrCommit: bytesToBase64url(value.proposalOrCommit),
    ...(value.moreProposals === undefined ? {} : { moreProposals: value.moreProposals.map(bytesToBase64url) }),
    ...(value.welcome === undefined ? {} : { welcome: bytesToBase64url(value.welcome) }), ...(value.groupInfo === undefined ? {} : { groupInfo: bytesToBase64url(value.groupInfo) }), ...(value.ratchetTree === undefined ? {} : { ratchetTree: bytesToBase64url(value.ratchetTree) }),
  }
}
