// DIDComm transport binding for the Conversation Group DS
// (docs/protocols/mls-ds-1.0.md), Phase 2b -- the second access path to the
// SAME engine/authorizer Phase 2a's HTTP handler (mls-ds/http.ts) calls.
// Nothing here re-implements DS logic; it only translates between a
// DidCommPlaintext and the authorizer function calls http.ts already makes,
// same as PLAN_biset-mls-ds.md's "engine is transport-agnostic" premise.
//
// Request/response shape (mls-ds-1.0.md §7): a pull gets an explicit
// response plaintext threaded via `thid`; a submit/publish/drop gets NO
// response to the SUBMITTER on success and a `problem-report` on failure.
// message-submit is the one exception with a side effect beyond its own
// response: a successful one fans out message-notify to the rest of the
// group (fanout.ts) before this function returns.
import { buildPlaintext, type DidCommPlaintext } from '../didcomm/message.ts'
import { buildProblemReport } from '../didcomm/problems.ts'
import { bytesToBase64url } from '../protocol/canonical.ts'
import type { SendDidCommMessageOptions } from '../didcomm/send-message.ts'
import { fanOutApplicationMessage } from './fanout.ts'
import {
  clearConversationPendingRemovals,
  createConversationGroup,
  dropConversationKeyPackages,
  publishConversationKeyPackages,
  pullConversationDeliveries,
  pullConversationGroupInfo,
  pullConversationGroupsFor,
  pullConversationKeyPackageCount,
  submitConversationCommit,
  submitConversationExternalCommit,
  submitConversationMessage,
  submitConversationSelfRemove,
  takeConversationKeyPackage,
  type ConversationDsSignatureVerifier,
} from './authorizer.ts'
import {
  ConversationDsWireError,
  decodeConversationCommitSubmitWire,
  decodeConversationDeliveriesPullWire,
  decodeConversationExternalCommitSubmitWire,
  decodeConversationGroupCreateWire,
  decodeConversationGroupInfoPullWire,
  decodeConversationGroupsForPullWire,
  decodeConversationKeyPackageCountPullWire,
  decodeConversationKeyPackageDropWire,
  decodeConversationKeyPackagePublishWire,
  decodeConversationKeyPackageTakeWire,
  decodeConversationMessageSubmitWire,
  decodeConversationPendingRemovalsClearWire,
  decodeConversationSelfRemoveSubmitWire,
} from '../protocol/conversation-mls-ds-wire.ts'
import type { ConversationGroupInfoAnswer, ConversationLogEntry, SqliteConversationDeliveryService } from './store.ts'
import * as T from './didcomm-types.ts'

/** A commit-shaped result's rejection reason, mapped 1:1 to mls-ds-1.0.md
 * §11's `code` values -- the same vocabulary mls-ds/store.ts's
 * `ConversationCommitResult` already uses, just prefixed. */
function commitErrorCode(reason: string): string { return `e.p.${reason}` }

export async function handleConversationDsMessage(
  ds: SqliteConversationDeliveryService,
  verifier: ConversationDsSignatureVerifier,
  msg: DidCommPlaintext,
  self: string,
  sendOpts: SendDidCommMessageOptions,
): Promise<DidCommPlaintext | null> {
  const sender = msg.from
  if (!sender) return problem(self, 'unknown', 'e.p.unauthorized', 'no sender on request', msg)
  let bodyText: string
  try {
    bodyText = JSON.stringify(msg.body)
  } catch {
    return problem(self, sender, 'e.p.unauthorized', 'request body is not serializable', msg)
  }

  try {
    if (msg.type === T.GROUP_CREATE) {
      const outcome = await createConversationGroup(ds, verifier, decodeConversationGroupCreateWire(bodyText))
      return outcome.ok ? null : problem(self, sender, 'e.p.unauthorized', 'group-create rejected', msg)
    }

    if (msg.type === T.COMMIT_SUBMIT) {
      const result = await submitConversationCommit(ds, verifier, decodeConversationCommitSubmitWire(bodyText))
      return result.ok ? null : problem(self, sender, commitErrorCode(result.reason), 'commit-submit rejected', msg)
    }

    if (msg.type === T.COMMIT_SUBMIT_EXTERNAL) {
      const result = await submitConversationExternalCommit(ds, verifier, decodeConversationExternalCommitSubmitWire(bodyText))
      return result.ok ? null : problem(self, sender, commitErrorCode(result.reason), 'commit-submit-external rejected', msg)
    }

    if (msg.type === T.GROUP_INFO_PULL) {
      const result = await pullConversationGroupInfo(ds, verifier, decodeConversationGroupInfoPullWire(bodyText))
      if (!result.ok) return problem(self, sender, 'e.p.unauthorized', 'group-info-pull rejected', msg)
      return respond(self, sender, T.GROUP_INFO, groupInfoBody(result.answer), msg)
    }

    if (msg.type === T.KEYPACKAGE_PUBLISH) {
      const count = await publishConversationKeyPackages(ds, verifier, decodeConversationKeyPackagePublishWire(bodyText))
      return count === undefined ? problem(self, sender, 'e.p.unauthorized', 'keypackage-publish rejected', msg) : null
    }

    if (msg.type === T.KEYPACKAGE_TAKE) {
      const request = decodeConversationKeyPackageTakeWire(bodyText)
      const taken = await takeConversationKeyPackage(ds, verifier, request)
      if (taken === undefined) return problem(self, sender, 'e.p.no-key-package', 'no KeyPackage available or request unauthorized', msg)
      return respond(self, sender, T.KEYPACKAGE_TAKEN, { package: bytesToBase64url(taken.keyPackage) }, msg)
    }

    if (msg.type === T.KEYPACKAGE_DROP) {
      const ok = await dropConversationKeyPackages(ds, verifier, decodeConversationKeyPackageDropWire(bodyText))
      return ok ? null : problem(self, sender, 'e.p.unauthorized', 'keypackage-drop rejected', msg)
    }

    if (msg.type === T.KEYPACKAGE_COUNT_PULL) {
      const count = await pullConversationKeyPackageCount(ds, verifier, decodeConversationKeyPackageCountPullWire(bodyText))
      if (count === undefined) return problem(self, sender, 'e.p.unauthorized', 'keypackage-count-pull rejected', msg)
      return respond(self, sender, T.KEYPACKAGE_COUNT, { count }, msg)
    }

    if (msg.type === T.GROUPS_FOR_PULL) {
      const groups = await pullConversationGroupsFor(ds, verifier, decodeConversationGroupsForPullWire(bodyText))
      if (groups === undefined) return problem(self, sender, 'e.p.unauthorized', 'groups-for-pull rejected', msg)
      return respond(self, sender, T.GROUPS_FOR, { groupIds: groups.map(g => g.groupId) }, msg)
    }

    if (msg.type === T.SELF_REMOVE_SUBMIT) {
      const result = await submitConversationSelfRemove(ds, verifier, decodeConversationSelfRemoveSubmitWire(bodyText))
      return result.ok ? null : problem(self, sender, commitErrorCode(result.reason), 'self-remove-submit rejected', msg)
    }

    if (msg.type === T.PENDING_REMOVALS_CLEAR) {
      const ok = await clearConversationPendingRemovals(ds, verifier, decodeConversationPendingRemovalsClearWire(bodyText))
      return ok ? null : problem(self, sender, 'e.p.unauthorized', 'pending-removals-clear rejected', msg)
    }

    if (msg.type === T.DELIVERIES_PULL) {
      const entries = await pullConversationDeliveries(ds, verifier, decodeConversationDeliveriesPullWire(bodyText))
      if (entries === undefined) return problem(self, sender, 'e.p.unauthorized', 'deliveries-pull rejected', msg)
      return respond(self, sender, T.DELIVERIES, deliveriesBody(entries), msg)
    }

    if (msg.type === T.MESSAGE_SUBMIT) {
      const request = decodeConversationMessageSubmitWire(bodyText)
      const result = await submitConversationMessage(ds, verifier, request)
      if (!result.ok) return problem(self, sender, commitErrorCode(result.reason), 'message-submit rejected', msg)
      // submitMessage always produces exactly one 'application' entry
      // (mls-ds/store.ts) -- fan it out to everyone but the sender before
      // acknowledging (silently, per this file's own response convention).
      await fanOutApplicationMessage(request.groupId, request.senderKid, result.entries[0]!, result.roster, sendOpts)
      return null
    }

    return problem(self, sender, 'e.p.not-a-member', `unsupported Conversation DS message type: ${msg.type}`, msg)
  } catch (err) {
    if (err instanceof ConversationDsWireError) return problem(self, sender, 'e.p.unauthorized', err.message, msg)
    throw err
  }
}

function respond(self: string, to: string, type: string, body: Record<string, unknown>, request: DidCommPlaintext): DidCommPlaintext {
  return buildPlaintext(type, body, self, to, { thid: request.id })
}

function problem(self: string, to: string, code: string, comment: string, request: DidCommPlaintext): DidCommPlaintext {
  return buildProblemReport(self, to, code, comment, { pthid: request.thid ?? request.id, ack: [request.id] })
}

function groupInfoBody(answer: ConversationGroupInfoAnswer): Record<string, unknown> {
  return { ...(answer.groupInfo ? { groupInfo: bytesToBase64url(answer.groupInfo) } : {}), pendingRemovals: answer.pendingRemovals }
}

function deliveriesBody(entries: ConversationLogEntry[]): Record<string, unknown> {
  return { entries: entries.map(e => ({ seq: e.seq, kind: e.kind, payload: bytesToBase64url(e.payload), epoch: e.epoch, at: e.at })) }
}
