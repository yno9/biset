/** Creation of the single-user Self/Vault MIMI room.
 *
 * The room ID is an opaque random provider URI.  It is intentionally separate
 * from the MLS GroupId: MIMI routes by room URI while MLS keeps its GroupId
 * cryptographic and opaque. */
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url, equalBytes } from '../protocol/canonical.ts'
import { createMlsGroup, confirmCommit, generateOwnKeyPackage, groupInfoEpoch, groupInfoForExternalJoin, joinGroupExternally } from './group.ts'
import type { MlsDeviceCredentialV2 } from './device-credential.ts'
import { createCommit, encodeMlsMessage } from './vendor/index.ts'
import { encodeCredential } from './vendor/credential.ts'
import { mlsSuite } from './suite.ts'
import { decryptWithLabel } from './vendor/crypto/hpke.ts'
import { encodeMimiFrankingAgent, encodeMimiParticipantListUpdate, encodeMimiRoomMetadata } from '../mimi/app-data.ts'
import { deliveriesPullSigningBytes, groupInfoRequestSigningBytes, groupInfoResponseSigningBytes, updateRoomSigningBytes } from '../mimi/authorizer.ts'
import { decodeGroupInfoRatchetTreeBundle } from '../mimi/wire.ts'
import { memberIdOf } from './identity.ts'
import type { MimiClientMode, MimiClientTransport } from './mimi-client-transport.ts'
import type { VisibleCredential } from '../mimi/protocol-types.ts'
import type { MimiVaultSessionStateStore } from './mimi-vault-session.ts'

export interface CreateMimiVaultRoomOptions {
  identityId: string
  /** Full device URI (`did…#kid`), never an account or mail address. */
  deviceId: string
  selfGroupId: string
  credential: MlsDeviceCredentialV2
  signaturePrivateKey: Uint8Array
  transport: MimiClientTransport
  stateStore: MimiVaultSessionStateStore
  mode?: MimiClientMode
  providerHost?: string
  now?: () => Date
}

export interface CreatedMimiVaultRoom { roomId: string; credential: VisibleCredential }

export interface JoinMimiVaultRoomOptions {
  identityId: string
  deviceId: string
  selfGroupId: string
  roomId: string
  credential: MlsDeviceCredentialV2
  signaturePrivateKey: Uint8Array
  transport: MimiClientTransport
  stateStore: MimiVaultSessionStateStore
  mode?: MimiClientMode
  now?: () => Date
}

/** Creates and durably records a fresh Self/Vault room.  Nothing is saved
 * locally before the hub has accepted the initial public MLS commit. */
export async function createMimiVaultRoom(options: CreateMimiVaultRoomOptions): Promise<CreatedMimiVaultRoom> {
  const mode = options.mode ?? 'self'
  const now = options.now ?? (() => new Date())
  const providerHost = options.providerHost ?? 'mimi-self.biset.md'
  if (!options.identityId || !options.deviceId || !options.selfGroupId || !/^[A-Za-z0-9.-]+$/.test(providerHost)) throw new TypeError('MIMI Vault room identity is invalid')
  const roomId = `mimi://${providerHost}/r/vault-${bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))}`
  const own = await generateOwnKeyPackage(options.credential, options.signaturePrivateKey)
  const sender: VisibleCredential = {
    kind: 'visible', user: options.identityId, client: options.deviceId,
    credential: encodeCredential(own.publicPackage.leafNode.credential), signaturePublicKey: own.publicPackage.leafNode.signaturePublicKey,
  }
  const franking = await options.transport.frankingAgent(mode, roomId)
  const state = await createMlsGroup(crypto.getRandomValues(new Uint8Array(32)), own)
  const proposal = (componentId: number, update: Uint8Array) => ({ proposalType: 'app_data_update' as const, appDataUpdate: { componentId, operation: 'update' as const, update } })
  const initial = await createCommit({ state, cipherSuite: await mlsSuite() }, {
    wireAsPublicMessage: true,
    extraProposals: [
      proposal(0x0021, encodeMimiFrankingAgent({ frankingSignatureKey: franking.frankingSignatureKey, credential: franking.credential })),
      proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [{ user: options.identityId, roleIndex: 1 }] })),
      proposal(0x0023, encodeMimiRoomMetadata({ roomUri: roomId, roomName: 'Biset Vault' })),
    ],
  })
  const unsigned = {
    version: 1 as const, protocol: 'mls10' as const, roomId, sender, epoch: '0',
    bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(initial.commit), groupInfo: await groupInfoForExternalJoin(initial.newState) },
    initialState: {
      basePolicy: new Uint8Array(), participantList: { participants: [{ user: options.identityId, roleIndex: 1, clientIds: [options.deviceId] }] },
      memberCredentials: [sender], metadata: { roomUri: roomId, roomName: 'Biset Vault' },
    }, submittedAt: now().toISOString(),
  }
  const response = await options.transport.update(mode, { ...unsigned, signature: ed25519.sign(updateRoomSigningBytes(unsigned), options.signaturePrivateKey) })
  if (response.status !== 'success') throw new Error(`MIMI Vault room creation failed: ${response.status}`)
  try {
    await options.stateStore.saveMimiVault(options.identityId, { roomId, selfGroupId: options.selfGroupId, state: initial.newState })
  } catch (error) {
    // The hub accepted the commit, so this process must not retain its
    // optimistic state as usable if persistence failed.  The caller can
    // recover by external joining the known room rather than double-creating.
    throw new Error('MIMI Vault room was accepted but local state could not be saved', { cause: error })
  }
  confirmCommit({ state: initial.newState, commit: encodeMlsMessage(initial.commit), consumed: initial.consumed })
  return { roomId, credential: sender }
}

/** Joins the already-existing self room from a newly restored device.
 *
 * The provider first HPKE-seals the current GroupInfo/tree to the fresh
 * device key. The external MLS commit then adds exactly that leaf. Its
 * acceptance is limited server-side to a DID that already owns the room;
 * this is not a general invitation mechanism. */
export async function joinMimiVaultRoom(options: JoinMimiVaultRoomOptions): Promise<VisibleCredential> {
  const mode = options.mode ?? 'self'
  const now = options.now ?? (() => new Date())
  if (!options.identityId || !options.deviceId || !options.selfGroupId || !options.roomId.startsWith('mimi://')) throw new TypeError('MIMI Vault external join identity is invalid')
  const own = await generateOwnKeyPackage(options.credential, options.signaturePrivateKey)
  const sender: VisibleCredential = {
    kind: 'visible', user: options.identityId, client: options.deviceId,
    credential: encodeCredential(own.publicPackage.leafNode.credential), signaturePublicKey: own.publicPackage.leafNode.signaturePublicKey,
  }
  const suite = await mlsSuite()
  const hpke = await suite.hpke.generateKeyPair()
  const groupInfoPublicKey = await suite.hpke.exportPublicKey(hpke.publicKey)
  const request = {
    version: 1 as const, protocol: 'mls10' as const, cipherSuite: 1, requester: sender,
    groupInfoPublicKey, requestedAt: now().toISOString(),
  }
  const response = await options.transport.groupInfo(mode, options.roomId, {
    ...request, signature: ed25519.sign(groupInfoRequestSigningBytes(request), options.signaturePrivateKey),
  })
  if (response.status !== 'success' || !response.signature || !response.hubSenderSignatureKey || !response.encryptedGroupInfoAndTree) throw new Error(`MIMI Vault external join GroupInfo failed: ${response.status}`)
  if (!ed25519.verify(response.signature, groupInfoResponseSigningBytes(response), response.hubSenderSignatureKey)) throw new Error('MIMI Vault external join GroupInfo signature is invalid')
  const plaintext = await decryptWithLabel(
    hpke.privateKey, 'GroupInfo and ratchet_tree encryption', new TextEncoder().encode(options.roomId),
    response.encryptedGroupInfoAndTree.kemOutput, response.encryptedGroupInfoAndTree.ciphertext, suite.hpke,
  )
  const groupInfo = decodeGroupInfoRatchetTreeBundle(plaintext).groupInfo
  const joined = await joinGroupExternally(groupInfo, own)
  const members: VisibleCredential[] = []
  for (const node of joined.state.ratchetTree) {
    if (node?.nodeType !== 'leaf') continue
    const member = memberIdOf(node.leaf.credential)
    if (member.did !== options.identityId) throw new Error('MIMI Vault external join found a non-owner member')
    members.push({ kind: 'visible', user: member.did, client: member.kid, credential: encodeCredential(node.leaf.credential), signaturePublicKey: node.leaf.signaturePublicKey })
  }
  if (!members.some(member => member.client === options.deviceId && equalPublicKey(member.signaturePublicKey, sender.signaturePublicKey))) throw new Error('MIMI Vault external join did not add this device')
  const clientIds = [...new Set(members.map(member => member.client))]
  const unsigned = {
    version: 1 as const, protocol: 'mls10' as const, roomId: options.roomId, sender, epoch: String(groupInfoEpoch(groupInfo)),
    bundle: { kind: 'commit' as const, proposalOrCommit: joined.commit, groupInfo: await groupInfoForExternalJoin(joined.state) },
    stateUpdate: { participantList: { participants: [{ user: options.identityId, roleIndex: 1, clientIds }] }, memberCredentials: members },
    submittedAt: now().toISOString(),
  }
  const accepted = await options.transport.update(mode, { ...unsigned, signature: ed25519.sign(updateRoomSigningBytes(unsigned), options.signaturePrivateKey) })
  if (accepted.status !== 'success') throw new Error(`MIMI Vault external join commit failed: ${accepted.status}`)
  // A new member cannot decrypt application ciphertexts from before its own
  // external commit (MLS forward secrecy). Start its provider cursor at that
  // commit so the next ordinary sync waits for a fresh post-join checkpoint
  // from an existing device instead of trying to replay old chunks.
  const deliveryCursor = await externalJoinDeliveryCursor(options, sender, joined.commit)
  try {
    await options.stateStore.saveMimiVault(options.identityId, { roomId: options.roomId, selfGroupId: options.selfGroupId, state: joined.state, deliveryCursor })
  } catch (error) {
    throw new Error('MIMI Vault external join was accepted but local state could not be saved', { cause: error })
  }
  confirmCommit(joined)
  return sender
}

function equalPublicKey(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

async function externalJoinDeliveryCursor(options: JoinMimiVaultRoomOptions, sender: VisibleCredential, commit: Uint8Array): Promise<number> {
  let afterSeq = 0
  for (let page = 0; page < 1024; page++) {
    const unsigned = { version: 1 as const, roomId: options.roomId, requester: sender, afterSeq, requestedAt: (options.now ?? (() => new Date()))().toISOString() }
    const entries = await options.transport.pullDeliveries(options.mode ?? 'self', { ...unsigned, signature: ed25519.sign(deliveriesPullSigningBytes(unsigned), options.signaturePrivateKey) })
    const ownCommit = entries.find(entry => entry.kind === 'commit' && equalBytes(entry.payload, commit))
    if (ownCommit) return ownCommit.seq
    if (entries.length < 32) break
    afterSeq = entries.at(-1)!.seq
  }
  throw new Error('MIMI Vault external join commit was accepted but its delivery was not found')
}
