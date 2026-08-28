import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToBase64url, equalBytes } from '../protocol/canonical.ts'
import { assertVaultId, assertVaultMemberId, mlsEpoch, type DeliverySeq, type VaultId, type VaultMemberId } from '../protocol/ids.ts'
import { vaultGroupViewHash, vaultGroupViewSigningBytes, type VaultGroupViewV1 } from '../protocol/vault-group-view.ts'
import {
  addMembers,
  confirmCommit,
  createMlsGroupWithAuthenticationService,
  decodeKeyPackage,
  decodeStateWithAuthenticationService,
  encodeKeyPackage,
  encodeState,
  generateOwnKeyPackageForCredential,
  joinMlsGroupWithAuthenticationService,
  ownSignaturePrivateKey,
  rekey,
  type OwnKeyPackage,
} from './group.ts'
import type { AuthenticationService, ClientState, Credential } from './vendor/index.ts'

const MEMBER_ID = /^vmb_[A-Za-z0-9_-]{43}$/
const GROUP_LABEL = 'biset/vault-mls-group/v1\0'
const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

/** Vault credentials are opaque member IDs; membership is authorized by MLS commits. */
export const vaultAuthenticationService: AuthenticationService = {
  async validateCredential(credential, signaturePublicKey) {
    try { vaultMemberIdOf(credential) } catch { return false }
    return signaturePublicKey.length === 32
  },
}

export function randomVaultId(): VaultId {
  return `vlt_${bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))}`
}

export function randomVaultMemberId(): VaultMemberId {
  return `vmb_${bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))}`
}

export function vaultMlsGroupId(vaultId: VaultId): Uint8Array {
  assertVaultId(vaultId)
  return sha256(encoder.encode(`${GROUP_LABEL}${vaultId}`))
}

export function vaultCredentialFor(memberId: VaultMemberId): Credential {
  assertVaultMemberId(memberId)
  if (!MEMBER_ID.test(memberId)) throw new TypeError('Vault member ID must contain 256 random bits')
  return { credentialType: 'basic', identity: encoder.encode(memberId) }
}

export function vaultMemberIdOf(credential: Credential): VaultMemberId {
  if (credential.credentialType !== 'basic') throw new TypeError('Vault MLS credential must be basic')
  const memberId = decoder.decode(credential.identity)
  if (!MEMBER_ID.test(memberId)) throw new TypeError('Vault MLS credential is invalid')
  return memberId
}

export interface VaultMlsGenesis {
  vaultId: VaultId
  memberId: VaultMemberId
  state: ClientState
  encodedState: Uint8Array
  memberSignaturePrivateKey: Uint8Array
  groupView: VaultGroupViewV1
}

/** Private, one-shot material prepared by a device that wants to join a
 * Vault. Only encodedKeyPackage is published; ownKeyPackage must stay local
 * until the Welcome has been consumed. */
export interface VaultMlsJoinCandidate {
  memberId: VaultMemberId
  ownKeyPackage: OwnKeyPackage
  encodedKeyPackage: Uint8Array
  memberSignaturePrivateKey: Uint8Array
}

export interface PendingVaultMlsAdd {
  memberId: VaultMemberId
  encodedState: Uint8Array
  groupView: VaultGroupViewV1
  commit: Uint8Array
  welcome: Uint8Array
  /** Retires the previous epoch's key material after the DS accepted this
   * exact transition and the new local state was durably written. */
  confirm(): void
}

export function assertVaultMlsBinding(input: {
  encodedState: Uint8Array
  groupView: VaultGroupViewV1
  localMemberId: VaultMemberId
  memberSignaturePrivateKey: Uint8Array
}): void {
  const state = decodeStateWithAuthenticationService(input.encodedState, vaultAuthenticationService)
  const context = state.groupContext
  if (!equalBytes(context.groupId, input.groupView.groupId) || mlsEpoch(context.epoch) !== input.groupView.groupEpoch || !equalBytes(context.confirmedTranscriptHash, input.groupView.confirmedTranscriptHash)) throw new TypeError('Vault MLS state does not match the accepted group view')
  const ownNode = state.ratchetTree[state.privatePath.leafIndex * 2]
  if (ownNode?.nodeType !== 'leaf' || vaultMemberIdOf(ownNode.leaf.credential) !== input.localMemberId || !equalBytes(ownNode.leaf.signaturePublicKey, ed25519.getPublicKey(input.memberSignaturePrivateKey)) || !equalBytes(state.signaturePrivateKey, input.memberSignaturePrivateKey)) throw new TypeError('Vault MLS state does not match the local member key')
  assertStateMembersMatchView(state, input.groupView)
}

/** Creates a real one-member MLS group with no public-identity credential. */
export async function createVaultMlsGenesis(deliveryFloor: DeliverySeq = '1'): Promise<VaultMlsGenesis> {
  const vaultId = randomVaultId()
  const memberId = randomVaultMemberId()
  const own = await generateOwnKeyPackageForCredential(vaultCredentialFor(memberId))
  const initial = await createMlsGroupWithAuthenticationService(vaultMlsGroupId(vaultId), own, vaultAuthenticationService)
  // The library's epoch-0 transcript hash is empty. Adopt an ordinary empty
  // commit so the persisted genesis routing view binds a real 32-byte MLS
  // confirmed transcript hash.
  const advanced = await rekey(initial)
  confirmCommit(advanced)
  const state = advanced.state
  const memberSignaturePrivateKey = ownSignaturePrivateKey(state).slice()
  const unsigned = {
    version: 1 as const,
    vaultId,
    groupId: state.groupContext.groupId.slice(),
    groupEpoch: mlsEpoch(state.groupContext.epoch),
    confirmedTranscriptHash: state.groupContext.confirmedTranscriptHash.slice(),
    previousViewHash: null,
    members: [{ memberId, signaturePublicKey: ed25519.getPublicKey(memberSignaturePrivateKey), deliveryFloor }],
    installerMemberId: memberId,
  }
  const groupView: VaultGroupViewV1 = { ...unsigned, signature: ed25519.sign(vaultGroupViewSigningBytes(unsigned), memberSignaturePrivateKey) }
  return { vaultId, memberId, state, encodedState: encodeState(state), memberSignaturePrivateKey, groupView }
}

/** Generates the private/public KeyPackage pair for an opaque second device. */
export async function createVaultMlsJoinCandidate(): Promise<VaultMlsJoinCandidate> {
  const memberId = randomVaultMemberId()
  const ownKeyPackage = await generateOwnKeyPackageForCredential(vaultCredentialFor(memberId))
  return {
    memberId,
    ownKeyPackage,
    encodedKeyPackage: encodeKeyPackage(ownKeyPackage.publicPackage),
    memberSignaturePrivateKey: ownKeyPackage.privatePackage.signaturePrivateKey.slice(),
  }
}

export function restoreVaultMlsJoinCandidate(value: {
  memberId: VaultMemberId
  encodedKeyPackage: Uint8Array
  initPrivateKey: Uint8Array
  hpkePrivateKey: Uint8Array
  signaturePrivateKey: Uint8Array
}): VaultMlsJoinCandidate {
  const publicPackage = decodeKeyPackage(value.encodedKeyPackage)
  if (vaultMemberIdOf(publicPackage.leafNode.credential) !== value.memberId || value.signaturePrivateKey.length !== 32 || !equalBytes(publicPackage.leafNode.signaturePublicKey, ed25519.getPublicKey(value.signaturePrivateKey))) throw new TypeError('persisted Vault MLS join candidate is invalid')
  const ownKeyPackage: OwnKeyPackage = { publicPackage, privatePackage: { initPrivateKey: value.initPrivateKey.slice(), hpkePrivateKey: value.hpkePrivateKey.slice(), signaturePrivateKey: value.signaturePrivateKey.slice() } }
  return { memberId: value.memberId, ownKeyPackage, encodedKeyPackage: value.encodedKeyPackage.slice(), memberSignaturePrivateKey: value.signaturePrivateKey.slice() }
}

/** Creates (but does not yet confirm) the MLS Add, Welcome, and signed routing
 * view. The caller must submit these as one DS transition before persisting
 * encodedState and invoking confirm(). */
export async function prepareVaultMlsAdd(
  current: {
    encodedState: Uint8Array
    groupView: VaultGroupViewV1
    localMemberId: VaultMemberId
    memberSignaturePrivateKey: Uint8Array
  },
  encodedKeyPackage: Uint8Array,
  deliveryFloor: DeliverySeq,
): Promise<PendingVaultMlsAdd> {
  assertVaultMlsBinding(current)
  const state = decodeStateWithAuthenticationService(current.encodedState, vaultAuthenticationService)
  const keyPackage = decodeKeyPackage(encodedKeyPackage)
  const memberId = vaultMemberIdOf(keyPackage.leafNode.credential)
  if (current.groupView.members.some(member => member.memberId === memberId)) throw new TypeError('Vault member is already present')
  const advanced = await addMembers(state, [keyPackage])
  if (!advanced.welcome) throw new Error('Vault MLS Add did not produce a Welcome')
  const nextMembers = membersOfState(advanced.state)
  const oldFloors = new Map(current.groupView.members.map(member => [member.memberId, member.deliveryFloor]))
  const members = nextMembers.map(member => ({
    ...member,
    deliveryFloor: member.memberId === memberId ? deliveryFloor : oldFloors.get(member.memberId)!,
  }))
  if (members.some(member => member.deliveryFloor === undefined) || members.length !== current.groupView.members.length + 1) throw new Error('Vault MLS Add produced an unexpected member set')
  const unsigned = {
    version: 1 as const,
    vaultId: current.groupView.vaultId,
    groupId: advanced.state.groupContext.groupId.slice(),
    groupEpoch: mlsEpoch(advanced.state.groupContext.epoch),
    confirmedTranscriptHash: advanced.state.groupContext.confirmedTranscriptHash.slice(),
    previousViewHash: vaultGroupViewHash(current.groupView),
    members,
    installerMemberId: current.localMemberId,
  }
  const groupView: VaultGroupViewV1 = { ...unsigned, signature: ed25519.sign(vaultGroupViewSigningBytes(unsigned), current.memberSignaturePrivateKey) }
  let confirmed = false
  return {
    memberId,
    encodedState: encodeState(advanced.state),
    groupView,
    commit: advanced.commit,
    welcome: advanced.welcome,
    confirm() {
      if (confirmed) return
      confirmed = true
      confirmCommit(advanced)
    },
  }
}

/** Consumes a Welcome and verifies that its full MLS tree equals the accepted
 * Coordinator routing view before returning persistable private state. */
export async function joinVaultMlsFromWelcome(
  candidate: VaultMlsJoinCandidate,
  welcome: Uint8Array,
  acceptedView: VaultGroupViewV1,
): Promise<{ encodedState: Uint8Array; memberSignaturePrivateKey: Uint8Array }> {
  const state = await joinMlsGroupWithAuthenticationService(welcome, candidate.ownKeyPackage, vaultAuthenticationService)
  const encodedState = encodeState(state)
  assertVaultMlsBinding({
    encodedState,
    groupView: acceptedView,
    localMemberId: candidate.memberId,
    memberSignaturePrivateKey: candidate.memberSignaturePrivateKey,
  })
  return { encodedState, memberSignaturePrivateKey: candidate.memberSignaturePrivateKey.slice() }
}

function membersOfState(state: ClientState): Array<{ memberId: VaultMemberId; signaturePublicKey: Uint8Array }> {
  const members: Array<{ memberId: VaultMemberId; signaturePublicKey: Uint8Array }> = []
  for (const node of state.ratchetTree) {
    if (node?.nodeType !== 'leaf') continue
    members.push({ memberId: vaultMemberIdOf(node.leaf.credential), signaturePublicKey: node.leaf.signaturePublicKey.slice() })
  }
  if (new Set(members.map(member => member.memberId)).size !== members.length) throw new TypeError('Vault MLS state contains duplicate member credentials')
  return members
}

function assertStateMembersMatchView(state: ClientState, view: VaultGroupViewV1): void {
  const stateMembers = membersOfState(state)
  if (stateMembers.length !== view.members.length) throw new TypeError('Vault MLS member set does not match the accepted group view')
  const viewMembers = new Map(view.members.map(member => [member.memberId, member.signaturePublicKey]))
  for (const member of stateMembers) {
    const expected = viewMembers.get(member.memberId)
    if (!expected || !equalBytes(expected, member.signaturePublicKey)) throw new TypeError('Vault MLS member set does not match the accepted group view')
  }
}
