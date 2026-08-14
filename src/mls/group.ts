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
  generateKeyPackage, createApplicationMessage, createCommit, createProposal,
  processMessage, encodeMlsMessage, decodeMlsMessage, mlsExporter, zeroOutUint8Array,
  defaultCapabilities, defaultLifetime, emptyPskIndex, acceptAll,
  encodeGroupState, decodeGroupState,
  defaultAuthenticationService, defaultKeyRetentionConfig, defaultLifetimeConfig,
  defaultKeyPackageEqualityConfig, defaultPaddingConfig,
  type AuthenticationService, type Capabilities, type ClientConfig, type ClientState, type KeyPackage,
  type PrivateKeyPackage, type Proposal, type Welcome,
} from './vendor/index.ts'
import { encodeGroupInfo, decodeGroupInfo, ratchetTreeFromExtension } from './vendor/groupInfo.ts'
import { makeKeyPackageRef } from './vendor/keyPackage.ts'
import { mlsSuite } from './suite.ts'
import { credentialFor, memberIdOf, didOfKid, type MlsMemberId } from './identity.ts'
import { encodeTransportKeys, deviceTransportKeys, TRANSPORT_KEYS_EXTENSION, type DeviceTransportKeys } from './transport-keys.ts'

// The Authentication Service (PLANMLS.md §2's AS role). ts-mls asks this
// whether a leaf's credential really belongs to the signature key in that leaf;
// its own default answers "yes" to everything, which is exactly the hole
// Phase 2 fills by resolving the DID URL in the credential and checking the
// fragment is still a listed key.
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
function clientConfig(): ClientConfig {
  return {
    keyRetentionConfig: defaultKeyRetentionConfig,
    lifetimeConfig: defaultLifetimeConfig,
    keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
    paddingConfig: defaultPaddingConfig,
    authService,
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
  | { state: ClientState; kind: 'message'; message: Uint8Array }

/** What this identity's own devices advertise. `defaultCapabilities()` plus
 * the private-use extension a leaf carries its transport keys in — a leaf
 * whose capabilities omit an extension it carries is rejected by the group
 * (RFC 9420 §7.2), so the two are declared together and never separately. */
function mlsCapabilities(): Capabilities {
  const base = defaultCapabilities()
  return { ...base, extensions: [...base.extensions, TRANSPORT_KEYS_EXTENSION] }
}

/** Generate this device's key package. `kid` is its DIDComm device key id
 * (`did#kN`) — see identity.ts for why that, and only that, is the credential.
 *
 * `transport` puts this device's DIDComm keys in its own leaf
 * (mls/transport-keys.ts), which is what lets any member rebuild the identity's
 * DID document from group state alone instead of reading it back. Optional
 * only so a group can be formed by something that has no transport keys to
 * announce — a test, or a future non-device member. */
export async function generateOwnKeyPackage(kid: string, transport?: { x25519: Uint8Array; mlkem?: Uint8Array }): Promise<OwnKeyPackage> {
  const suite = await mlsSuite()
  const leafExtensions = transport ? [encodeTransportKeys(transport.x25519, transport.mlkem)] : []
  const kp = await generateKeyPackage(credentialFor(kid), mlsCapabilities(), defaultLifetime, [], suite, leafExtensions)
  return { publicPackage: kp.publicPackage, privatePackage: kp.privatePackage }
}

/** Every device in the group with the transport keys its own leaf announces —
 * the whole input needed to publish this identity's DID document, taken from
 * group state and nothing else.
 *
 * A leaf without readable keys, or one whose kid contradicts them, is absent
 * rather than guessed at (transport-keys.ts's check). That device is still a
 * member; it just cannot be published until it re-announces. */
export function memberTransportKeys(state: ClientState, did: string): DeviceTransportKeys[] {
  const out: DeviceTransportKeys[] = []
  for (const node of state.ratchetTree) {
    if (node?.nodeType !== 'leaf') continue
    const keys = deviceTransportKeys(node.leaf)
    if (keys && didOfKid(keys.kid) === did) out.push(keys)
  }
  return out
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
  const suite = await mlsSuite()
  return createGroup(groupId, own.publicPackage, own.privatePackage, [], suite, clientConfig())
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
 * it. */
export async function removeMembers(state: ClientState, kids: string[]): Promise<CommitResult> {
  const members = memberList(state)
  const proposals: Proposal[] = kids.map(kid => {
    const found = members.find(m => m.kid === kid)
    if (!found) throw new Error(`removeMembers: not a member: ${kid}`)
    return { proposalType: 'remove', remove: { removed: found.leafIndex } }
  })
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
export async function proposeSelfRemoval(state: ClientState): Promise<{ state: ClientState; proposal: Uint8Array }> {
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

async function commitWith(state: ClientState, extraProposals: Proposal[], ratchetTreeExtension = false): Promise<CommitResult> {
  const suite = await mlsSuite()
  const result = await createCommit({ state, cipherSuite: suite }, { extraProposals, ratchetTreeExtension })
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
  const suite = await mlsSuite()
  const msg = decodeMlsMessage(welcomeBytes, 0)?.[0]
  if (msg?.wireformat !== 'mls_welcome') throw new Error(`joinMlsGroup: not a welcome (${msg?.wireformat ?? 'undecodable'})`)
  return joinGroup(msg.welcome, own.publicPackage, own.privatePackage, emptyPskIndex, suite, ratchetTree, undefined, clientConfig())
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
  return result.kind === 'applicationMessage'
    ? { state: result.newState, kind: 'message', message: result.message }
    : { state: result.newState, kind: 'state' }
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

/** Every device key id a given identity has in this group. */
export function memberKids(state: ClientState, did: string): string[] {
  return memberList(state).filter(m => m.did === did).map(m => m.kid)
}

// ------------------------------------------------------- external commits
//
// How a NEW DEVICE of an identity that is already in a group joins it without
// waiting for one of that identity's other devices to be online and add it.
//
// The alternative — "an existing device must add you" — is the safer default
// for a stranger, and it is what `addMembers` does. But for one's OWN devices
// it would be a real regression: today a restored device is usable the moment
// the seed is entered, because holding the seed lets it publish itself into
// its own DID document. External commits keep exactly that property, and the
// check that makes it safe is the same one the DID layer already performs:
// the joiner's credential is `did#kN`, and the AS resolves that DID and
// verifies the fragment is a currently-listed key of it (mls/authservice.ts).
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
export async function joinGroupExternally(groupInfoBytes: Uint8Array, own: OwnKeyPackage): Promise<CommitResult> {
  const suite = await mlsSuite()
  const groupInfo = decodeGroupInfo(groupInfoBytes, 0)?.[0]
  if (groupInfo === undefined) throw new Error('joinGroupExternally: undecodable group info')
  const { publicMessage, newState } = await joinGroupExternal(
    groupInfo, own.publicPackage, own.privatePackage,
    // `resync` false: this is a new leaf joining, not a device replacing its
    // own existing leaf after losing state. Resync would remove the old leaf,
    // which for a genuinely new device would remove somebody else's.
    false, suite, undefined, clientConfig(),
  )
  return {
    state: newState,
    commit: encodeMlsMessage({ publicMessage, wireformat: 'mls_public_message', version: 'mls10' }),
    consumed: [],
  }
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
export function groupInfoContainsKid(groupInfoBytes: Uint8Array, kid: string): boolean | undefined {
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
  const decoded = decodeGroupState(bytes, 0)?.[0]
  if (decoded === undefined) throw new Error('decodeState: undecodable group state')
  return { ...decoded, clientConfig: clientConfig() }
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
export function isActiveMember(state: ClientState, kid: string): boolean {
  if (state.groupActiveState.kind !== 'active') return false
  return memberList(state).some(m => m.kid === kid)
}

/** The group's current epoch. MLS counts epochs as a 64-bit integer, so this
 * is a bigint — never let one reach JSON.stringify (it throws); the persisted
 * form is `encodeGroupState`'s bytes, not JSON (see store.ts). */
export function epochOf(state: ClientState): bigint {
  return state.groupContext.epoch
}
