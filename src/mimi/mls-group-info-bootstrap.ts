/**
 * Bootstraps a `PublicGroupState` (src/mls/vendor/publicGroupState.ts) from
 * a GroupInfo -- this is what answers PLAN_biset-mimi-server.md §21.4's
 * open question ("how does a hub learn a room's genesis confirmationTag,
 * which isn't derivable from public data alone"). GroupInfo already carries
 * exactly that (RFC 9420: `GroupInfoTBS.confirmationTag`), bundled with the
 * groupContext and (via the ratchet_tree extension) the tree itself, all
 * under one signature by a real member (`GroupInfoTBS.signer`, a leaf
 * index resolved from the *same* embedded tree) -- no separate provenance
 * mechanism is needed. `HandshakeBundle.groupInfo` (protocol-types.ts) is
 * already an existing, optional wire field biset's own client produces via
 * `groupInfoForExternalJoin` (src/mls/group.ts) using bare `encodeGroupInfo`
 * (not MLSMessage-wrapped, matching that same client convention for
 * Welcome) -- decoding it here is genuinely new, since biset-mimi has so
 * far only ever stored these bytes opaquely for HPKE-sealed re-delivery to
 * an external-join requester (group-info.ts).
 */
import { decodeGroupInfo } from '../vendor/mls/groupInfo.js'
import { getSignaturePublicKeyFromLeafIndex } from '../vendor/mls/ratchetTree.js'
import { toLeafIndex } from '../vendor/mls/treemath.js'
import type { CiphersuiteImpl } from '../vendor/mls/crypto/ciphersuite.js'
import { verifyGroupInfoSignature, ratchetTreeFromExtension } from '../vendor/mls/groupInfo.js'
import { initialPublicGroupState, type PublicGroupState } from '../vendor/mls/publicGroupState.js'
import type { AuthenticationService } from '../vendor/mls/authenticationService.js'

export class MimiGroupInfoBootstrapError extends Error {}

/** Decodes and fully verifies a bare-encoded GroupInfo, returning the
 * PublicGroupState it attests to. Throws MimiGroupInfoBootstrapError on any
 * decode/verification failure -- callers should treat that as an outright
 * rejection, the same as any other malformed/untrusted room-creation input. */
export async function bootstrapPublicGroupStateFromGroupInfo(
  groupInfoBytes: Uint8Array, authService: AuthenticationService, cs: CiphersuiteImpl,
): Promise<PublicGroupState> {
  const decoded = decodeGroupInfo(groupInfoBytes, 0)
  if (!decoded || decoded[1] !== groupInfoBytes.length) throw new MimiGroupInfoBootstrapError('groupInfo is not a complete GroupInfo structure')
  const [groupInfo] = decoded
  const ratchetTree = ratchetTreeFromExtension(groupInfo)
  if (!ratchetTree) throw new MimiGroupInfoBootstrapError('groupInfo has no ratchet_tree extension')
  let signerKey: Uint8Array
  try { signerKey = getSignaturePublicKeyFromLeafIndex(ratchetTree, toLeafIndex(groupInfo.signer)) } catch { throw new MimiGroupInfoBootstrapError('groupInfo.signer does not name a real leaf in its own ratchet_tree') }
  if (!(await verifyGroupInfoSignature(groupInfo, signerKey, cs.signature))) throw new MimiGroupInfoBootstrapError('groupInfo signature does not verify against its own ratchet_tree')
  const state = await initialPublicGroupState(ratchetTree, groupInfo.groupContext, authService, cs)
  // initialPublicGroupState has no confirmationTag input of its own -- a
  // GroupInfo is exactly the one place this otherwise-unrecoverable value
  // (see this module's own doc comment) comes from, so it must be carried
  // through here rather than left at that function's own placeholder.
  return { ...state, confirmationTag: groupInfo.confirmationTag }
}
