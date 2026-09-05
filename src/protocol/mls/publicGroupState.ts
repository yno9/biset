/**
 * biset: new module. A "public group state" tracker usable by a non-member
 * observer holding no private MLS key material at all -- concretely, a
 * MIMI hub. RFC 9420's Delivery-Service model, and MIMI spec §9 ("actors
 * authenticate their identities to the hub server using the MLS
 * PublicMessage signed object format, together with the identity
 * credentials presented in MLS") and §7.4 (a follower's own proposal
 * authority is via the group's standard `external_senders` extension, kept
 * current by ordinary commits), both assume exactly this: the hub tracks
 * enough of the group's *public* structure -- the ratchet tree, GroupContext,
 * and each leaf's public signature key -- to verify a PublicMessage's own
 * signature and apply a commit's tree/GroupContext effects, without ever
 * holding an epoch secret. See PLAN_biset-mimi-server.md §21.
 *
 * This reuses `applyProposals` (already the single, tested, real
 * implementation of proposal-grouping, tree mutation, and app-data
 * replacement) via a placeholder `ClientState`. Every field on that
 * placeholder that is private-key material is either read only inside
 * `applyProposals`'s `external_init` branch (whose *tree* effect --
 * `treeAfterRemove`, `newMemberLeafIndex` -- is still fully public; the
 * `externalInitSecret` it also computes from the placeholder is discarded,
 * never trusted downstream) or not read at all on the code paths this
 * module exercises. What this module can *not* do, by MLS design and not
 * by omission, is verify a commit's confirmation tag or a PublicMessage's
 * membership tag -- both derive from epoch secrets only real members hold.
 * A hub can authenticate *authorship* (the FramedContent signature) and
 * *structural consistency* (tree/parent hashes, transcript hash chaining);
 * verifying that the epoch secrets a commit produces are themselves
 * internally consistent is left to the real members, same as any RFC 9420
 * Delivery Service.
 */
import type { CiphersuiteImpl } from './crypto/ciphersuite.js'
import type { GroupContext } from './groupContext.js'
import type { RatchetTree } from './ratchetTree.js'
import { addLeafNode } from './ratchetTree.js'
import { treeHashRoot } from './treeHash.js'
import type { UnappliedProposals } from './unappliedProposals.js'
import type { AuthenticationService } from './authenticationService.js'
import { defaultClientConfig } from './clientConfig.js'
import type { ClientState } from './clientState.js'
import { applyProposals, validateLeafNodeUpdateOrCommit, validateRatchetTree, nextEpochContext } from './clientState.js'
import { applyUpdatePath } from './updatePath.js'
import { emptyPskIndex } from './pskIndex.js'
import { findSignaturePublicKey } from './publicMessage.js'
import type { PublicMessage } from './publicMessage.js'
import { verifyFramedContentSignature } from './framedContent.js'
import { nodeToLeafIndex, toLeafIndex } from './treemath.js'
import { ValidationError } from './mlsError.js'

/** @public */
export interface PublicGroupState {
  groupContext: GroupContext
  ratchetTree: RatchetTree
  /** The most recently applied commit's confirmationTag -- public (it rides
   * in the commit's own auth data), and is itself an input to the next
   * commit's transcript-hash chaining (nextEpochContext). */
  confirmationTag: Uint8Array
  /** Direct (non-reference) proposals only, matching the existing MIMI
   * AppSync extraction's own scope decision (mls-appsync.ts rejects
   * ProposalRef commits outright) -- always empty for now. */
  unappliedProposals: UnappliedProposals
}

/** Builds the initial tracked state from a room's genesis commit's own
 * ratchet_tree + the GroupContext implied by that commit's own content
 * (epoch, groupId, extensions) -- the caller is responsible for having
 * already decoded both from the genesis PublicMessage/HandshakeBundle. */
export async function initialPublicGroupState(
  ratchetTree: RatchetTree, groupContext: GroupContext, authService: AuthenticationService, cs: CiphersuiteImpl,
): Promise<PublicGroupState> {
  const err = await validateRatchetTree(ratchetTree, groupContext, defaultClientConfig.lifetimeConfig, authService, groupContext.treeHash, cs)
  if (err) throw err
  return { groupContext, ratchetTree, confirmationTag: new Uint8Array(0), unappliedProposals: {} }
}

/** Verifies a PublicMessage's own FramedContent signature against the
 * correct key for its sender (member: the tracked tree's leaf; external:
 * the group's external_senders extension; new_member_*: the message's own
 * self-attested leaf) -- independent of commit application, usable for a
 * standalone application/proposal message too. */
export async function verifyPublicMessageSignature(state: PublicGroupState, message: PublicMessage, wireformat: 'mls_public_message', cs: CiphersuiteImpl): Promise<boolean> {
  const signKey = findSignaturePublicKey(state.ratchetTree, state.groupContext, message.content)
  return verifyFramedContentSignature(signKey, wireformat, message.content, message.auth, state.groupContext, cs.signature)
}

/**
 * Verifies and applies one Commit-type PublicMessage against the tracked
 * state, returning the resulting state. Throws (does not return an error
 * value) on any signature/structural failure -- callers should treat any
 * throw as an outright rejection of the commit, same as a real member would.
 */
export async function applyPublicCommit(
  state: PublicGroupState, message: PublicMessage, authService: AuthenticationService, cs: CiphersuiteImpl,
): Promise<PublicGroupState> {
  if (message.content.contentType !== 'commit') throw new ValidationError('applyPublicCommit requires a Commit')
  if (message.auth.contentType !== 'commit') throw new ValidationError('Commit content requires commit auth data')
  if (message.content.epoch !== state.groupContext.epoch) throw new ValidationError('Commit is not for the tracked epoch')
  if (!(await verifyPublicMessageSignature(state, message, 'mls_public_message', cs))) throw new ValidationError('Commit signature does not verify against the tracked tree')

  const senderLeafIndex = message.content.sender.senderType === 'member' ? toLeafIndex(message.content.sender.leafIndex) : undefined
  const placeholder = placeholderClientState(state, authService)
  const result = await applyProposals(placeholder, message.content.commit.proposals, senderLeafIndex, emptyPskIndex, false, cs)

  const groupContextWithExtensions = result.additionalResult.kind === 'memberCommit' && result.additionalResult.extensions.length > 0
    ? { ...state.groupContext, extensions: result.additionalResult.extensions } : state.groupContext

  let tree = result.tree
  if (message.content.commit.path !== undefined) {
    const additionalResult = result.additionalResult
    // A member commit's UpdatePath applies against its own existing leaf
    // (already present in `result.tree`) -- no tree-shape change needed
    // first. An external commit's new leaf does NOT exist in `result.tree`
    // yet (applyProposals's externalCommit branch only computes *where* it
    // will eventually land, via findBlankLeafNodeIndexOrExtend, without
    // inserting it): addLeafNode must actually extend the tree first, the
    // same way the real (member-side) processCommit does in
    // processMessages.ts's applyTreeUpdate. Skipping this and calling
    // applyUpdatePath directly against the un-extended tree fed treemath
    // functions (filteredDirectPath et al.) a leaf index outside the
    // tree's actual width -- not a throw, an infinite loop (found live,
    // 2026-09-02, via test/mls/mimi-vault-room.test.ts hanging).
    const committerLeafIndex = senderLeafIndex ?? (() => {
      if (additionalResult.kind !== 'externalCommit') throw new ValidationError('Cannot verify commit leaf node because no committer leaf index found')
      const [extended, leafNodeIndex] = addLeafNode(tree, message.content.commit.path!.leafNode)
      tree = extended
      return nodeToLeafIndex(leafNodeIndex)
    })()
    const leafErr = await validateLeafNodeUpdateOrCommit(message.content.commit.path.leafNode, committerLeafIndex, groupContextWithExtensions, authService, cs.signature)
    if (leafErr) throw leafErr
    tree = await applyUpdatePath(tree, committerLeafIndex, message.content.commit.path, cs.hash, additionalResult.kind === 'externalCommit')
  } else if (result.needsUpdatePath) {
    throw new ValidationError('Update path is required')
  }

  const newTreeHash = await treeHashRoot(tree, cs.hash)
  const updatedGroupContext = await nextEpochContext(groupContextWithExtensions, 'mls_public_message', message.content, message.auth.signature, newTreeHash, state.confirmationTag, cs.hash)

  return { groupContext: updatedGroupContext, ratchetTree: tree, confirmationTag: message.auth.confirmationTag, unappliedProposals: {} }
}

/** Every field here is either unread on the code paths this module
 * exercises, or (keySchedule.externalSecret only) read solely to compute a
 * value (`externalInitSecret`) this module discards -- see the module doc
 * comment above for exactly which. None of it is real key material; a hub
 * genuinely has none, since it is never an MLS group member. */
function placeholderClientState(state: PublicGroupState, authService: AuthenticationService): ClientState {
  return {
    groupContext: state.groupContext,
    ratchetTree: state.ratchetTree,
    unappliedProposals: state.unappliedProposals,
    confirmationTag: state.confirmationTag,
    keySchedule: {
      senderDataSecret: new Uint8Array(0), exporterSecret: new Uint8Array(0), externalSecret: new Uint8Array(32),
      confirmationKey: new Uint8Array(0), membershipKey: new Uint8Array(0), resumptionPsk: new Uint8Array(0),
      epochAuthenticator: new Uint8Array(0), initSecret: new Uint8Array(0),
    },
    secretTree: [],
    privatePath: { leafIndex: 0, privateKeys: {} },
    signaturePrivateKey: new Uint8Array(0),
    historicalReceiverData: new Map(),
    groupActiveState: { kind: 'active' },
    clientConfig: { ...defaultClientConfig, authService },
  }
}
