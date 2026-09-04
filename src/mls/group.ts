// biset's MLS group operations — the whole RFC 9420 surface the rest of the
// app is allowed to see.
//
// Everything here is **platform-free** (no DOM, no IndexedDB, no fetch) for the
// same reason `src/did/` is: the anchor's DS role (PLANMLS.md §4 Phase 1) and
// the browser client both need to reason about MLS objects, and the client's
// tests run under Bun. Persistence lives in `mls/store.ts`, transport in
// `did/didcomm/mls-transport.ts`; neither is imported from here.
//
// Two conventions run through every function:
//
//   - **State is immutable.** ts-mls returns a new `ClientState` rather than
//     mutating; callers must adopt the returned one. Keeping the old state and
//     using it again is the classic MLS footgun (reusing a consumed key), so
//     every function here returns `{ state, ... }` and never anything that
//     tempts a caller to keep the input around.
//   - **Consumed key material is zeroed.** ts-mls hands back the secrets an
//     operation retired (`consumed`); leaving them in memory would undo the
//     forward secrecy the group is here for.
import {
  createGroup, joinGroup, joinGroupExternal, createGroupInfoWithExternalPubAndRatchetTree,
  generateKeyPackage, generateKeyPackageWithKey, createApplicationMessage, createCommit, createProposal,
  processMessage, encodeMlsMessage, decodeMlsMessage, mlsExporter, zeroOutUint8Array,
  defaultCapabilities, defaultLifetime, emptyPskIndex, acceptAll,
  APP_DATA_DICTIONARY_EXTENSION_TYPE, APP_DATA_UPDATE_PROPOSAL_TYPE,
  encodeGroupState, decodeGroupState,
  defaultAuthenticationService, defaultKeyRetentionConfig, defaultLifetimeConfig,
  defaultKeyPackageEqualityConfig, defaultPaddingConfig,
  type AuthenticationService, type Capabilities, type ClientConfig, type ClientState, type Credential, type KeyPackage,
  type PrivateKeyPackage, type Proposal, type Welcome,
} from './vendor/index.ts'
import { encodeGroupInfo, decodeGroupInfo, ratchetTreeFromExtension } from './vendor/groupInfo.ts'
import { makeKeyPackageRef } from './vendor/keyPackage.ts'
import { mlsSuite } from './suite.ts'
import { credentialFor, memberIdOf, type MlsMemberId } from './identity.ts'
import { mlsDeviceCredentialOf, type MlsDeviceCredentialV2 } from './device-credential.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sameIdentity } from '../identity/idkey.ts'
import { equalBytes } from '../protocol/canonical.ts'

// The Authentication Service (PLANMLS.md §2's AS role). ts-mls asks this
// whether a leaf's credential really belongs to the signature key in that leaf;
// its own default answers "yes" to everything, which is exactly the hole
// production service fills by resolving the stable Root Key and validating
// the generation-bound device credential against the actual leaf key.
//
// It is a settable module-level hook rather than a parameter because it must
// apply to state restored from disk too, where no call site is nearby to pass
// it — and because there is only ever one AS for the app.
let authService: AuthenticationService = defaultAuthenticationService

/** Install the DID-backed credential validator (Phase 2). Until then the
 * default accept-all service runs, and a leaf's DID claim is unverified. */
export function setMlsAuthService(service: AuthenticationService): void { authService = service }

/** The client configuration every group of ours is created, joined and
 * restored with. `decodeGroupState` deliberately does NOT carry config — it is
 * policy, not state — so restoring a group means re-attaching this. */
function clientConfig(authenticationService: AuthenticationService = authService): ClientConfig {
  return {
    keyRetentionConfig: defaultKeyRetentionConfig,
    lifetimeConfig: defaultLifetimeConfig,
    keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
    paddingConfig: defaultPaddingConfig,
    authService: authenticationService,
  }
}

/** This device's key package: the public half is handed out (via the
 * mediator's KeyPackage Store), the private half must be kept until someone
 * uses it to add us — at which point `joinMlsGroup` consumes it. */
export interface OwnKeyPackage { publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }

/** A commit, plus the Welcome it produced (if the commit added anyone). Both
 * are already MLS-encoded wire bytes, ready to be handed to the transport.
 *
 * `consumed` is the key material this commit retires. It is deliberately NOT
 * zeroed yet — see confirmCommit. */
export interface CommitResult { state: ClientState; commit: Uint8Array; welcome?: Uint8Array; consumed: Uint8Array[] }

/** Zero the key material a commit retired. Call this ONLY once the Delivery
 * Service has accepted the commit — i.e. once `state` is really the group's
 * next state and the state it came from will never be used again.
 *
 * The ordering matters and is not hygiene. A commit is submitted optimistically:
 * another member may have committed from the same epoch first, in which case
 * this one is refused and the caller must fall back to the state it committed
 * FROM, apply the winner, and try again. ts-mls's states share their buffers
 * with the state they were derived from, so zeroing at commit-creation time
 * destroys the very state the retry depends on — the fallback state then fails
 * to process the winning commit with "Could not verify confirmation tag",
 * which is how this was found (test/mls-e2e.test.ts's epoch-conflict case).
 * On a conflict, drop the CommitResult and zero nothing. */
export function confirmCommit(result: CommitResult): void {
  result.consumed.forEach(zeroOutUint8Array)
}

/** What arrived: either the group advanced (commit/proposal applied) or it was
 * an application message and `message` is the plaintext. */
export type IncomingResult =
  | { state: ClientState; kind: 'state' }
  | { state: ClientState; kind: 'message'; message: Uint8Array; sender?: MlsMemberId }

/** Generate this device's KeyPackage with its fixed leaf signing key and
 * generation-bound device credential.
 *
 * biset's DIDComm transport keys (X25519/ML-KEM, carried in the leaf as a
 * private-use extension in the pre-rewrite implementation) are not part of
 * this boundary — they belong to the DIDComm adapter (PLAN.md §6.1,
 * unimplemented), which the roster/vault path this module serves does not
 * need. */
export async function generateOwnKeyPackage(value: MlsDeviceCredentialV2, signaturePrivateKey: Uint8Array): Promise<OwnKeyPackage> {
  if (!equalBytes(ed25519.getPublicKey(signaturePrivateKey), value.signaturePublicKey)) throw new TypeError('MLS device credential does not match the signing private key')
  const suite = await mlsSuite()
  const kp = await generateKeyPackageWithKey(
    credentialFor(value), capabilitiesWithRoomMetadataSupport(), defaultLifetime, [],
    { signKey: signaturePrivateKey, publicKey: value.signaturePublicKey }, suite, [],
  )
  return { publicPackage: kp.publicPackage, privatePackage: kp.privatePackage }
}

/** Generates a KeyPackage for an application-defined BasicCredential. */
export async function generateOwnKeyPackageForCredential(credential: Credential): Promise<OwnKeyPackage> {
  const suite = await mlsSuite()
  const kp = await generateKeyPackage(credential, capabilitiesWithRoomMetadataSupport(), defaultLifetime, [], suite, [])
  return { publicPackage: kp.publicPackage, privatePackage: kp.privatePackage }
}

/** `defaultCapabilities()` plus a declared understanding of the room-metadata
 * private-use extension (ROOM_METADATA_EXTENSION_TYPE, defined further down
 * this file) -- RFC 9420 requires every leaf ADDED to a group to declare
 * capability support for whatever non-default extensions are ALREADY active
 * in that group's GroupContext (vendor/clientState.ts's Add-proposal
 * validation), so a KeyPackage generated without this fails to join ANY
 * Conversation Group that already has a room name set (found live,
 * 2026-09-01: "Added leaf node that doesn't support extension in
 * GroupContext" for exactly this reason). Declared unconditionally, on
 * every KeyPackage this app ever generates (including Self Group leaves,
 * which will simply never encounter the extension) -- the alternative, a
 * second capabilities set used only for Conversation Group KeyPackages,
 * would be the exact kind of divergent-but-parallel implementation this
 * codebase avoids elsewhere. */
function capabilitiesWithRoomMetadataSupport(): Capabilities {
  const base = defaultCapabilities()
  return {
    ...base,
    extensions: [...base.extensions, ROOM_METADATA_EXTENSION_TYPE, APP_DATA_DICTIONARY_EXTENSION_TYPE],
    proposals: [...base.proposals, APP_DATA_UPDATE_PROPOSAL_TYPE],
  }
}

/** MLS wire encoding of a key package — what gets published and fetched. */
export function encodeKeyPackage(kp: KeyPackage): Uint8Array {
  return encodeMlsMessage({ keyPackage: kp, wireformat: 'mls_key_package', version: 'mls10' })
}

/** Inverse of `encodeKeyPackage`. Throws on anything that isn't one, rather
 * than returning undefined: a caller that fetched a key package and got a
 * welcome has a transport bug, not an empty result. */
export function decodeKeyPackage(bytes: Uint8Array): KeyPackage {
  const msg = decodeMlsMessage(bytes, 0)?.[0]
  if (msg?.wireformat !== 'mls_key_package') throw new Error(`decodeKeyPackage: not a key package (${msg?.wireformat ?? 'undecodable'})`)
  return msg.keyPackage
}

/** A key package's MLS reference (hex) — the id a Welcome uses to say WHICH
 * key package it was encrypted to (`EncryptedGroupSecrets.newMember`).
 *
 * This is how a device with several published key packages finds the private
 * half a given Welcome needs, without trial decryption. `makeKeyPackageRef`
 * is not re-exported from ts-mls's index, hence the subpath import; it is a
 * plain hash of the encoded key package, and pairing it with
 * `welcomeRecipientRefs` below is the only thing biset uses it for. */
export async function keyPackageRefOf(kp: KeyPackage): Promise<string> {
  const suite = await mlsSuite()
  return toHex(await makeKeyPackageRef(kp, suite.hash))
}

/** The key package refs (hex) a Welcome carries secrets for. Ours is whichever
 * of these we have a private half for — see mls/store.ts. */
export function welcomeRecipientRefs(welcomeBytes: Uint8Array): string[] {
  const msg = decodeMlsMessage(welcomeBytes, 0)?.[0]
  if (msg?.wireformat !== 'mls_welcome') throw new Error(`welcomeRecipientRefs: not a welcome (${msg?.wireformat ?? 'undecodable'})`)
  return msg.welcome.secrets.map(s => toHex(s.newMember))
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

/** Create a group with only us in it. `groupId` is the application's own id
 * for the conversation (biset uses a random 32-byte value, see store.ts). */
export async function createMlsGroup(groupId: Uint8Array, own: OwnKeyPackage): Promise<ClientState> {
  return createMlsGroupWithAuthenticationService(groupId, own, authService)
}

async function createMlsGroupWithAuthenticationService(groupId: Uint8Array, own: OwnKeyPackage, authenticationService: AuthenticationService): Promise<ClientState> {
  const suite = await mlsSuite()
  return createGroup(groupId, own.publicPackage, own.privatePackage, [], suite, clientConfig(authenticationService))
}

/** Commit an Add for each of `keyPackages`. The returned `welcome` goes to the
 * new members, the `commit` to the existing ones — both through the DS, which
 * is what decides the order these land in for everybody (PLANMLS.md §2). */
export async function addMembers(state: ClientState, keyPackages: KeyPackage[]): Promise<CommitResult> {
  const proposals: Proposal[] = keyPackages.map(keyPackage => ({ proposalType: 'add', add: { keyPackage } }))
  // The ratchet tree rides IN the Welcome (`ratchetTreeExtension`). MLS also
  // allows fetching it out of band, which would keep Welcomes small — but the
  // only party positioned to serve it is the DS, and that would mean the DS
  // holding group structure it otherwise never needs, plus a second round trip
  // on the one path (joining) where a client has nothing to fall back on. A
  // self-contained Welcome is the simpler and less centralized of the two.
  return commitWith(state, proposals, true)
}

/** Commit a Remove for a member, named by its device key id (`did#kN`).
 * Removing an identity's *whole* membership means removing each of its
 * devices — resolve them with `memberKids` and pass them all in one commit, so
 * the group never sits in an epoch where some of a removed identity's devices
 * are still in it.
 *
 * The removed member cannot read anything sent afterwards, which is the entire
 * point and is NOT what upstream ts-mls does: it builds a single-Remove commit
 * without an UpdatePath, leaving the commit secret a zero buffer that the
 * removed member derives along with everyone else. The vendored fork fixes
 * that (`vendor/clientState.ts`'s `needsUpdatePath`), and
 * test/mls-core.test.ts pins the behaviour so a re-sync cannot quietly undo
 * it.
 *
 * `wireAsPublicMessage` has NO default on purpose. It used to default to
 * `false` for the since-deleted self-group.ts / conversation-group.ts
 * callers, and that default is wrong for the only caller left in the app:
 * mimi-vault-room.ts's removeMimiVaultDevice, whose commit goes to the MIMI
 * hub as a room-state update and is rejected with 400 ("room-state update
 * must be a complete MLS PublicMessage") unless it is `true`. Rather than
 * swap one silently-wrong default for another (the tests below deliberately
 * exercise the private-wire framing), every caller now has to say which wire
 * framing its delivery service expects. */
export async function removeMembers(state: ClientState, kids: string[], wireAsPublicMessage: boolean): Promise<CommitResult> {
  const members = memberList(state)
  const proposals: Proposal[] = kids.map(kid => {
    const found = members.find(m => m.kid === kid)
    if (!found) throw new Error(`removeMembers: not a member: ${kid}`)
    return { proposalType: 'remove', remove: { removed: found.leafIndex } }
  })
  return commitWith(state, proposals, false, undefined, wireAsPublicMessage)
}

/** Atomically advances this leaf's Sign-generation credential and removes
 * every stale sibling selected by the caller in the same MLS epoch. */
export async function rotateOwnCredentialAndRemoveMembers(state: ClientState, value: MlsDeviceCredentialV2, kids: string[]): Promise<CommitResult> {
  const members = memberList(state)
  const proposals: Proposal[] = kids.map(kid => {
    const found = members.find(member => member.kid === kid)
    if (!found) throw new Error(`rotateOwnCredentialAndRemoveMembers: not a member: ${kid}`)
    return { proposalType: 'remove', remove: { removed: found.leafIndex } }
  })
  return commitWith(state, proposals, false, credentialFor(value))
}

/** Like removeMembers, but by leaf index rather than kid. Needed exactly when
 * kid-based lookup breaks down: two leaves sharing the same kid (self-group.ts's
 * joinSelfGroup self-heal, for a device that lost its local group state and
 * rejoined under the SAME kid its old, never-removed leaf still carries) —
 * `members.find(m => m.kid === kid)` can only ever resolve to one of the two. */
async function removeLeavesByIndex(state: ClientState, leafIndices: number[]): Promise<CommitResult> {
  const proposals: Proposal[] = leafIndices.map(removed => ({ proposalType: 'remove', remove: { removed } }))
  return commitWith(state, proposals)
}

/** Propose this device's OWN removal from the group.
 *
 * A member cannot commit its own removal — RFC 9420 forbids a commit that
 * removes the committer, and `vendor/clientState.ts` enforces it. Proposing it
 * is allowed, and is the protocol's answer for "I want out": the proposal is
 * distributed like any other message, and the next member to commit anything
 * carries it (ts-mls bundles received proposals into the next commit
 * automatically, `bundleAllProposals`).
 *
 * The returned state has the proposal recorded but is otherwise unchanged —
 * this device is still a member until someone commits. That is the honest
 * state of affairs and the caller must not pretend otherwise: a device that
 * has proposed its own removal and then deleted its keys is gone for practical
 * purposes, but its leaf is in the tree until a sibling acts. See
 * mls/self-group.ts's leaveSelfGroup for what biset does about the case where
 * there is no sibling left to act. */
async function proposeSelfRemoval(state: ClientState): Promise<{ state: ClientState; proposal: Uint8Array }> {
  const suite = await mlsSuite()
  const removed = state.privatePath.leafIndex
  const result = await createProposal(state, true, { proposalType: 'remove', remove: { removed } }, suite)
  result.consumed.forEach(zeroOutUint8Array)
  return { state: result.newState, proposal: encodeMlsMessage(result.message) }
}

/** An empty commit — no membership change, just a fresh epoch. This is how
 * Post-Compromise Security is actually obtained: PCS is a property of *having
 * committed since* the compromise, not of the protocol standing still. */
export async function rekey(state: ClientState): Promise<CommitResult> {
  return commitWith(state, [])
}

// Room metadata (a Conversation Group's display name -- PLAN-mimi.md's own
// "biset conforms to MLS/JMAP/DIDComm/MIMI" scope). MIMI's actual mechanism
// (draft-ietf-mimi-protocol §5.3/§7.6) is an "AppSync" proposal with
// applicationId `mimiRoomPolicy`, defined by a SEPARATE, still-unstable
// companion draft (draft-barnes-mls-appsync) whose own IANA section reads
// "TODO: Register ApplicationData proposal" -- there is no assigned
// proposal_type to implement against yet, and building against an
// unassigned wire format would break the moment real numbers land.
//
// Until that stabilizes, this uses RFC 9420's OWN native `group_context_extensions`
// proposal (already fully implemented by this vendored library -- no core
// crypto changes needed) with a PRIVATE-USE extension type
// (ROOM_METADATA_EXTENSION_TYPE, 0xF000 -- RFC 9420's registries reserve
// 0xF000-0xFFFF for exactly this). This keeps the property MIMI's own
// design is actually FOR: the name lives in the group's own cryptographic
// state, converged via an ordinary commit like any membership change, and
// every future joiner inherits the CURRENT value automatically through
// their own Welcome's embedded GroupContext -- no separate propagation
// channel (a DIDComm invite field, PLAN-mimi.md's earlier, now-removed
// approach) is needed at all. It is NOT the eventual MIMI wire format; once
// draft-barnes-mls-appsync's proposal_type is assigned, this extension
// should be replaced by a real AppSync proposal carrying `mimiRoomPolicy`.
const ROOM_METADATA_EXTENSION_TYPE = 0xf000

export interface RoomMetadata {
  name?: string
}

/** The group's current room metadata, read live off `state.groupContext.extensions`
 * -- the same "ask the tree/context, don't cache a copy" principle
 * `memberList` already follows for membership. undefined for a group that
 * has never had one set (every Conversation Group before this feature, and
 * any created without a name). */
export function roomMetadataOf(state: ClientState): RoomMetadata | undefined {
  const extension = state.groupContext.extensions.find(e => e.extensionType === ROOM_METADATA_EXTENSION_TYPE)
  if (!extension) return undefined
  try {
    return JSON.parse(new TextDecoder().decode(extension.extensionData)) as RoomMetadata
  } catch {
    return undefined
  }
}

/** Commits a change to the group's room metadata -- any current member may
 * call this (no `canChangeRoomName`-style capability/role model exists for
 * Conversation Groups yet, the same scope cut already applied to
 * add/remove). Preserves every OTHER extension already on the group:
 * `group_context_extensions` proposal replaces the WHOLE extensions list
 * (RFC 9420), not just the one entry, so this reads the current list first
 * rather than assuming room metadata is the only extension ever present. */
export async function setRoomMetadata(state: ClientState, metadata: RoomMetadata): Promise<CommitResult> {
  const extensionData = new TextEncoder().encode(JSON.stringify(metadata))
  const extensions = [
    ...state.groupContext.extensions.filter(e => e.extensionType !== ROOM_METADATA_EXTENSION_TYPE),
    { extensionType: ROOM_METADATA_EXTENSION_TYPE, extensionData },
  ]
  const proposals: Proposal[] = [{ proposalType: 'group_context_extensions', groupContextExtensions: { extensions } }]
  return commitWith(state, proposals)
}

/** Commit a complete next value for an application component in the MLS
 * `app_data_dictionary`.  Component-specific update validation belongs to the
 * application that owns the component; this is the wire-level MLS primitive. */
export async function setAppDataComponent(state: ClientState, componentId: number, data: Uint8Array): Promise<CommitResult> {
  if (!Number.isInteger(componentId) || componentId < 0 || componentId > 0xffff) throw new TypeError('MLS component ID must be uint16')
  return commitWith(state, [{ proposalType: 'app_data_update', appDataUpdate: { componentId, operation: 'update', update: data } }], false, undefined, true)
}

async function commitWith(state: ClientState, extraProposals: Proposal[], ratchetTreeExtension = false, ownCredentialUpdate?: Credential, wireAsPublicMessage = false): Promise<CommitResult> {
  const suite = await mlsSuite()
  const result = await createCommit({ state, cipherSuite: suite }, { extraProposals, ratchetTreeExtension, wireAsPublicMessage, ...(ownCredentialUpdate ? { ownCredentialUpdate } : {}) })
  return {
    state: result.newState,
    commit: encodeMlsMessage(result.commit),
    welcome: result.welcome === undefined ? undefined : encodeWelcome(result.welcome),
    consumed: result.consumed,
  }
}

function encodeWelcome(welcome: Welcome): Uint8Array {
  return encodeMlsMessage({ welcome, wireformat: 'mls_welcome', version: 'mls10' })
}

/** Join from a Welcome. `ratchetTree` is the group's tree: MLS lets it ride in
 * the Welcome as an extension or be fetched out of band, and biset takes the
 * out-of-band route — the DS holds the tree (PLANMLS.md §4 Phase 1), which
 * keeps Welcomes small and, more importantly, keeps the tree out of a message
 * that has to be individually encrypted to every joiner. */
export async function joinMlsGroup(welcomeBytes: Uint8Array, own: OwnKeyPackage, ratchetTree?: ClientState['ratchetTree']): Promise<ClientState> {
  return joinMlsGroupWithAuthenticationService(welcomeBytes, own, authService, ratchetTree)
}

/** Join a group whose BasicCredential profile has its own authentication
 * service (the opaque Vault profile is the non-identity caller). */
async function joinMlsGroupWithAuthenticationService(
  welcomeBytes: Uint8Array,
  own: OwnKeyPackage,
  authenticationService: AuthenticationService,
  ratchetTree?: ClientState['ratchetTree'],
): Promise<ClientState> {
  const suite = await mlsSuite()
  const msg = decodeMlsMessage(welcomeBytes, 0)?.[0]
  if (msg?.wireformat !== 'mls_welcome') throw new Error(`joinMlsGroup: not a welcome (${msg?.wireformat ?? 'undecodable'})`)
  return joinGroup(msg.welcome, own.publicPackage, own.privatePackage, emptyPskIndex, suite, ratchetTree, undefined, clientConfig(authenticationService))
}

/** Encrypt an application message. The bytes returned are the innermost layer
 * of PLANMLS.md §3's three — opaque to the mediator, to the DS and to DIDComm
 * itself. */
export async function encryptApplication(state: ClientState, plaintext: Uint8Array): Promise<{ state: ClientState; wire: Uint8Array }> {
  const suite = await mlsSuite()
  const result = await createApplicationMessage(state, plaintext, suite)
  result.consumed.forEach(zeroOutUint8Array)
  return { state: result.newState, wire: encodeMlsMessage({ privateMessage: result.privateMessage, wireformat: 'mls_private_message', version: 'mls10' }) }
}

/** Process anything that arrived for this group — application message, commit
 * or proposal. One entry point on purpose: the receiver does not get to decide
 * what a message is, the wire format does. */
export async function processIncoming(state: ClientState, bytes: Uint8Array): Promise<IncomingResult> {
  const suite = await mlsSuite()
  const msg = decodeMlsMessage(bytes, 0)?.[0]
  if (msg === undefined) throw new Error('processIncoming: undecodable MLS message')
  if (msg.wireformat !== 'mls_private_message' && msg.wireformat !== 'mls_public_message') {
    throw new Error(`processIncoming: unexpected wire format ${msg.wireformat}`)
  }
  const result = await processMessage(msg, state, emptyPskIndex, acceptAll, suite)
  result.consumed.forEach(zeroOutUint8Array)
  if (result.kind !== 'applicationMessage') return { state: result.newState, kind: 'state' }
  // WHO sent it, taken from the leaf MLS just authenticated — not from
  // anything inside the plaintext. In a group of several people that
  // distinction is the difference between attribution and a name field any
  // member could fill in with someone else's.
  //
  // The leaf is read from the state the message was decrypted AGAINST, which
  // for a message from an epoch this device has already left is the historical
  // tree rather than the current one — the same reason the sender index is
  // taken here and not resolved later by the caller.
  const sender = result.senderLeafIndex === undefined ? undefined : memberAt(state, result.senderLeafIndex)
  return { state: result.newState, kind: 'message', message: result.message, ...(sender ? { sender } : {}) }
}

/** A symmetric key derived from the group's current epoch, for a purpose
 * OUTSIDE the MLS content itself — PLANMLS.md §3.3's metadata layer.
 *
 * Everything this protects inherits the group's forward secrecy and PCS for
 * free: the exporter secret changes with every commit, so a key derived here
 * is scoped to one epoch without any key management of its own. */
export async function exportSecret(state: ClientState, label: string, context: Uint8Array, length: number): Promise<Uint8Array> {
  const suite = await mlsSuite()
  return mlsExporter(state.keySchedule.exporterSecret, label, context, length, suite)
}

/** The member at one leaf index, or undefined when the leaf is empty — which
 * a message's sender leaf never is, since MLS authenticated it against that
 * leaf's key to get here. */
function memberAt(state: ClientState, leafIndex: number): MlsMemberId | undefined {
  const node = state.ratchetTree[leafIndex * 2]
  if (node?.nodeType !== 'leaf') return undefined
  try {
    return memberIdOf(node.leaf.credential)
  } catch {
    return undefined
  }
}

/** Everyone currently in the group, in leaf order. */
export function memberList(state: ClientState): Array<MlsMemberId & { leafIndex: number }> {
  const members: Array<MlsMemberId & { leafIndex: number }> = []
  state.ratchetTree.forEach((node, nodeIndex) => {
    // Leaves are the even node indices; leaf i lives at node 2i (RFC 9420 §4.1).
    if (node?.nodeType !== 'leaf') return
    members.push({ ...memberIdOf(node.leaf.credential), leafIndex: nodeIndex / 2 })
  })
  return members
}

/** The distinct identities in the group — devices of one identity collapse to
 * one entry, which is what a member list in the UI shows. */
export function memberDids(state: ClientState): string[] {
  return [...new Set(memberList(state).map(m => m.did))]
}

/** Every device key id a given identity has in this group.
 *
 * `sameIdentity`, not `===`: mid-migration (a did:webvh domain move,
 * identity/webvh/move.ts), some members' credentials already carry the new
 * did while others -- devices that haven't caught up yet -- still carry
 * the old one, same SCID either way. An exact match here would silently
 * drop the not-yet-migrated devices from every roster/vault-delivery
 * projection built from this list the moment the FIRST device migrated,
 * even though they are still cryptographically full members (found live,
 * 2026-08-26, chasing why an uninvolved second device got locked out of
 * vault delivery right after its sibling device performed a move). */
export function memberKids(state: ClientState, did: string): string[] {
  return memberList(state).filter(m => sameIdentity(m.did, did)).map(m => m.kid)
}

/** The ACTUAL MLS leaf signature key a member kid currently holds, or
 * undefined if it is not (or no longer) in the group. Same access pattern
 * webvh-authentication-service.ts's AS callback gets handed by ts-mls
 * itself; this is for a caller that instead needs to look one up by kid
 * directly — vault/crypto.ts's SegmentKeyWrap grantor verification
 * (`mls/segment-key-membership.ts`), which checks against CURRENT self-group
 * membership rather than a resolved DID document (PLAN.md §4.2: the self
 * group, not the DID, is the authority on who may grant a SegmentKey right
 * now). */
export function memberSignaturePublicKey(state: ClientState, kid: string): Uint8Array | undefined {
  for (const node of state.ratchetTree) {
    if (node?.nodeType !== 'leaf') continue
    try {
      if (memberIdOf(node.leaf.credential).kid === kid) return node.leaf.signaturePublicKey
    } catch {
      continue
    }
  }
  return undefined
}

export function memberDeviceCredentialBytes(state: ClientState, kid: string): Uint8Array | undefined {
  for (const node of state.ratchetTree) {
    if (node?.nodeType !== 'leaf') continue
    try {
      if (memberIdOf(node.leaf.credential).kid === kid && node.leaf.credential.credentialType === 'basic') return node.leaf.credential.identity.slice()
    } catch { continue }
  }
  return undefined
}

// ------------------------------------------------------- external commits
//
// How a NEW DEVICE of an identity that is already in a group joins it without
// waiting for one of that identity's other devices to be online and add it.
//
// The alternative — "an existing device must add you" — is the safer default
// for a stranger, and it is what `addMembers` does. But for one's OWN devices
// it would be a real regression: today a restored device is usable the moment
// the seed is entered, because holding the seed authorizes a new device
// credential. External commits keep exactly that property: the AS resolves
// the Root Key and verifies the credential's Root signature.
// The Delivery Service enforces the matching rule on its side — an external
// commit is admitted only when the joiner's DID is ALREADY in the roster, so
// this can add a device to an identity that is a member, and never an
// identity that isn't.

/** The GroupInfo an external joiner needs, carrying both the external public
 * key it commits against and the ratchet tree it builds its state from.
 *
 * Produced after every commit by whoever committed, and held by the DS. It is
 * NOT secret in the sense the group's key schedule is — it reveals the roster
 * and the tree structure, which the DS already knows — but it is only ever
 * handed to an authenticated member DID. */
export async function groupInfoForExternalJoin(state: ClientState): Promise<Uint8Array> {
  const suite = await mlsSuite()
  return encodeGroupInfo(await createGroupInfoWithExternalPubAndRatchetTree(state, [], suite))
}

/** Join a group we are not in, by committing ourselves into it.
 *
 * Returns the state AND the commit that must be delivered to the group — this
 * join is not complete until the DS accepts that commit, and if it loses its
 * epoch the whole result is discarded and retried against a fresh GroupInfo
 * (same rule as confirmCommit's). */
export async function joinGroupExternally(
  groupInfoBytes: Uint8Array,
  own: OwnKeyPackage,
  /** Narrow recovery override for a self-group whose prior leaves have all
   * been revoked from its owner's DID document. Normal joins always use the
   * installed DID Authentication Service. */
  authenticationService?: AuthenticationService,
  /** True only for a device replacing its OWN existing leaf (a did:webvh
   * domain move, identity/webvh/move.ts's own credential-migration step,
   * via generateOwnKeyPackageWithSignatureKey's matching signature key) —
   * the resulting commit atomically removes that leaf and adds this one.
   * False (the default) for a genuinely new device joining: resync would
   * remove whichever existing leaf's signature key happens to match `own`'s,
   * which for a new device is nobody's and must stay that way. */
  resync = false,
): Promise<CommitResult> {
  const suite = await mlsSuite()
  const groupInfo = decodeGroupInfo(groupInfoBytes, 0)?.[0]
  if (groupInfo === undefined) throw new Error('joinGroupExternally: undecodable group info')
  const { publicMessage, newState } = await joinGroupExternal(
    groupInfo, own.publicPackage, own.privatePackage,
    resync, suite, undefined, clientConfig(authenticationService),
  )
  return {
    state: newState,
    commit: encodeMlsMessage({ publicMessage, wireformat: 'mls_public_message', version: 'mls10' }),
    consumed: [],
  }
}

/** Credential kids carried by a GroupInfo ratchet tree. This is deliberately
 * structural only: callers that need to *trust* a leaf must still run it
 * through the Authentication Service. The self-group recovery path uses this
 * to identify already-revoked leaves which otherwise prevent the MLS library
 * from parsing the very GroupInfo needed to remove them. */
function groupInfoMemberKids(groupInfoBytes: Uint8Array): string[] | undefined {
  const groupInfo = decodeGroupInfo(groupInfoBytes, 0)?.[0]
  if (groupInfo === undefined) return undefined
  const tree = ratchetTreeFromExtension(groupInfo)
  if (tree === undefined) return undefined
  const kids: string[] = []
  for (const node of tree) {
    if (node?.nodeType !== 'leaf') continue
    try { kids.push(memberIdOf(node.leaf.credential).kid) } catch { return undefined }
  }
  return kids
}

/** Does the group described by this GroupInfo still contain `kid`?
 *
 * The one question local state cannot answer. A device removed while it was
 * offline has state that still says "active" with its own leaf in its own copy
 * of the tree — it never saw the commit. Asking the Delivery Service for the
 * current GroupInfo, which carries the ratchet tree, is what tells it
 * otherwise, and it is why biset's commits include that tree.
 *
 * Undefined when the GroupInfo carries no tree (another implementation's, or
 * one made before biset attached it) — "cannot tell", which the caller must
 * not read as either answer. */
function groupInfoContainsKid(groupInfoBytes: Uint8Array, kid: string): boolean | undefined {
  const groupInfo = decodeGroupInfo(groupInfoBytes, 0)?.[0]
  if (groupInfo === undefined) return undefined
  const tree = ratchetTreeFromExtension(groupInfo)
  if (tree === undefined) return undefined
  for (const node of tree) {
    if (node?.nodeType !== 'leaf') continue
    try {
      if (memberIdOf(node.leaf.credential).kid === kid) return true
    } catch { /* not one of ours */ }
  }
  return false
}

/** The epoch a GroupInfo describes — what an external joiner commits against,
 * and what the DS compares to decide whether that commit is still current. */
export function groupInfoEpoch(groupInfoBytes: Uint8Array): bigint {
  const groupInfo = decodeGroupInfo(groupInfoBytes, 0)?.[0]
  if (groupInfo === undefined) throw new Error('groupInfoEpoch: undecodable group info')
  return groupInfo.groupContext.epoch
}

/** Serialize a group for storage. The bytes are MLS's own TLS encoding of the
 * group state — never JSON: the epoch is a bigint (JSON.stringify throws on
 * one) and half the state is raw key material. */
export function encodeState(state: ClientState): Uint8Array {
  return encodeGroupState(state)
}

/** Restore a group from `encodeState`'s bytes, re-attaching the client config
 * (which is policy and deliberately not persisted — see clientConfig()). A
 * state restored WITHOUT it looks fine until the first message arrives and
 * then fails inside ts-mls on a missing keyRetentionConfig, so this pairing is
 * not optional and is why callers never touch decodeGroupState directly. */
export function decodeState(bytes: Uint8Array): ClientState {
  return decodeStateWithAuthenticationService(bytes, authService)
}

function decodeStateWithAuthenticationService(bytes: Uint8Array, authenticationService: AuthenticationService): ClientState {
  const decoded = decodeGroupState(bytes, 0)?.[0]
  if (decoded === undefined) throw new Error('decodeState: undecodable group state')
  return { ...decoded, clientConfig: clientConfig(authenticationService) }
}

/** Is this device still an active member of the group this state describes?
 *
 * Two ways to not be, and both look like ordinary state until asked: MLS marks
 * a member that processed its own removal `removedFromGroup`, and a device
 * whose leaf is simply absent from the tree was removed while it was not
 * watching (it never saw the commit). Either way the state is a record of a
 * membership that has ended, and using it as "I am in the group" is how a
 * removed device stays out forever — it short-circuits the rejoin that would
 * put it back. */
function isActiveMember(state: ClientState, kid: string): boolean {
  if (state.groupActiveState.kind !== 'active') return false
  return memberList(state).some(m => m.kid === kid)
}

/** The group's current epoch. MLS counts epochs as a 64-bit integer, so this
 * is a bigint — never let one reach JSON.stringify (it throws); the persisted
 * form is `encodeGroupState`'s bytes, not JSON (see store.ts). */
export function epochOf(state: ClientState): bigint {
  return state.groupContext.epoch
}

/** THIS device's own MLS leaf signature private key, straight off a stored
 * self-group `ClientState` — a `ClientState` only ever holds the key
 * material for the leaf it IS, never another member's, so this is the same
 * key `generateOwnKeyPackage`'s `OwnKeyPackage.privatePackage` held at join
 * time. What lets self-group.ts's `SelfGroupSigner` be reconstructed after a
 * restart without keeping the original `OwnKeyPackage` around separately
 * (identity/bootstrap.ts's `maintainSelfGroup`). */
export function ownSignaturePrivateKey(state: ClientState): Uint8Array {
  return state.signaturePrivateKey
}

export function ownMlsDeviceCredential(state: ClientState): MlsDeviceCredentialV2 {
  const ownPublicKey = ed25519.getPublicKey(state.signaturePrivateKey)
  for (const node of state.ratchetTree) {
    if (node?.nodeType !== 'leaf' || !equalBytes(node.leaf.signaturePublicKey, ownPublicKey)) continue
    return mlsDeviceCredentialOf(node.leaf.credential)
  }
  throw new Error('stored MLS state has no credential for its own signing key')
}
