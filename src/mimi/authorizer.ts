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
  KeyMaterialRequest,
  KeyMaterialResponse,
  KeyPackagePublishRequest,
  MimiCredential,
  MlsRequiredCapabilities,
  RoomStateUpdate,
  SubmitMessageRequest,
  UpdateRoomRequest,
  VisibleCredential,
} from './protocol-types.ts'
import type { SqliteMimiStore } from './store.ts'

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
    acceptableCiphersuites: value.acceptableCiphersuites, requiredCapabilities: capabilitiesValue(value.requiredCapabilities), requester: visibleCredentialValue(value.requester),
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
    label: 'biset/mimi-deliveries-pull/v1', version: value.version, roomId: value.roomId, requester: visibleCredentialValue(value.requester), afterSeq: value.afterSeq, requestedAt: value.requestedAt,
  })
}

export function deliveriesWatchSigningBytes(value: Omit<DeliveriesWatchRequest, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mimi-deliveries-watch/v1', version: value.version, roomId: value.roomId, requester: visibleCredentialValue(value.requester), requestedAt: value.requestedAt,
  })
}

export function submitMessageSigningBytes(value: Omit<SubmitMessageRequest, 'signature'>): Uint8Array {
  return canonicalBytes({ label: 'biset/mimi-submit-message/v1', version: value.version, protocol: value.protocol, roomId: value.roomId, sender: visibleCredentialValue(value.sender), epoch: value.epoch, appMessage: bytesToBase64url(value.appMessage), frankingTag: bytesToBase64url(value.frankAAD.frankingTag), frankingSignatureCiphersuite: value.frankingSignatureCiphersuite, submittedAt: value.submittedAt })
}

export async function authorizeUpdate(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: UpdateRoomRequest): Promise<boolean> {
  if (!(await verifier.verify(value.sender, updateRoomSigningBytes(value), value.signature))) return false
  const room = store.room(value.roomId)
  // An initial update is the one self-authenticated entry point.  Its signer
  // must be in `initialState`; the store enforces that invariant.  Once a
  // room exists, pin both user/client and public key to its persisted leaf.
  return room === undefined ? value.initialState !== undefined : credentialMatchesRoom(room, value.sender)
}

export async function authorizeKeyMaterial(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: KeyMaterialRequest): Promise<boolean> {
  if (value.requestingUser !== value.requester.user) return false
  if (!(await verifier.verify(value.requester, keyMaterialSigningBytes(value), value.signature))) return false
  const room = store.room(value.roomId)
  return room !== undefined && credentialMatchesRoom(room, value.requester)
}

export async function authorizeKeyPackagePublish(verifier: MimiSignatureVerifier, value: KeyPackagePublishRequest): Promise<boolean> {
  // Pseudonymous publication is intentionally deferred to Phase 2.
  if (value.credential.kind !== 'visible') return false
  return verifier.verify(value.credential, keyPackagePublishSigningBytes(value), value.signature)
}

export async function authorizeDeliveriesPull(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: DeliveriesPullRequest): Promise<boolean> {
  return (await verifier.verify(value.requester, deliveriesPullSigningBytes(value), value.signature)) && credentialMatchesRoom(store.room(value.roomId), value.requester)
}

export async function authorizeDeliveriesWatch(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: DeliveriesWatchRequest): Promise<boolean> {
  return (await verifier.verify(value.requester, deliveriesWatchSigningBytes(value), value.signature)) && credentialMatchesRoom(store.room(value.roomId), value.requester)
}

export async function authorizeSubmitMessage(store: SqliteMimiStore, verifier: MimiSignatureVerifier, value: SubmitMessageRequest): Promise<boolean> {
  return (await verifier.verify(value.sender, submitMessageSigningBytes(value), value.signature)) && credentialMatchesRoom(store.room(value.roomId), value.sender)
}

/** Turns the store's single-use KeyPackage take into draft §5.2 status data. */
export function keyMaterialResponse(targetUser: string, packages: ReturnType<SqliteMimiStore['takeKeyPackages']>): KeyMaterialResponse {
  if (packages.length === 0) return { protocol: 'mls10', user: targetUser, status: 'noCompatibleMaterial', clients: [] }
  return {
    protocol: 'mls10', user: targetUser, status: 'success',
    clients: packages.map(item => ({ client: item.client, status: 'success', keyPackage: item.keyPackage, capabilities: item.capabilities })),
  }
}

function credentialMatchesRoom(room: ReturnType<SqliteMimiStore['room']>, signer: MimiCredential): boolean {
  const user = signer.kind === 'visible' ? signer.user : signer.userPseudonym
  if (!room || !room.participantList.participants.some(participant => participant.user === user)) return false
  return room.memberCredentials.some(credential => credential.kind === signer.kind && equalBytes(credential.signaturePublicKey, signer.signaturePublicKey) && (credential.kind === 'visible' && signer.kind === 'visible' ? credential.client === signer.client : credential.kind === 'pseudonymous' && signer.kind === 'pseudonymous' ? credential.clientPseudonym === signer.clientPseudonym : false))
}

function visibleCredentialValue(value: VisibleCredential): CanonicalValue {
  return { kind: value.kind, user: value.user, client: value.client, credential: bytesToBase64url(value.credential), signaturePublicKey: bytesToBase64url(value.signaturePublicKey) }
}

function credentialValue(value: MimiCredential): CanonicalValue {
  if (value.kind === 'visible') return visibleCredentialValue(value)
  return {
    kind: value.kind, clientPseudonym: value.clientPseudonym, userPseudonym: value.userPseudonym,
    signaturePublicKey: bytesToBase64url(value.signaturePublicKey), identityLinkCiphertext: bytesToBase64url(value.identityLinkCiphertext), signature: bytesToBase64url(value.signature),
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
