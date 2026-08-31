// message-notify fan-out (docs/protocols/mls-ds-1.0.md §5.2, §6): the one
// push delivery this DS does. Everything else (group-info, deliveries,
// KeyPackages) is pull-only -- a member asks, the DS answers in the SAME
// request/response the didcomm.ts handler already builds. Application
// messages are the exception because fanning them out to everyone but the
// sender IS the point of routing them through a DS at all (PLAN-mimi.md's
// finding: this is the one operation Self Group's DS has no equivalent of).
import { sendFrontDoorMessage, type DidCommSendResult, type SendDidCommMessageOptions } from '../didcomm/front-door-send.ts'
import { bytesToBase64url } from '../protocol/canonical.ts'
import { didOfKid } from '../protocol/ids.ts'
import * as T from './didcomm-types.ts'
import type { ConversationLogEntry } from './store.ts'

export interface FanOutRecipientResult {
  kid: string
  result: DidCommSendResult
}

/** Delivers one application-message log entry to every current group member
 * OTHER than the sender. Best-effort per recipient -- one recipient's
 * unreachable provider does not fail the others (returns each result rather
 * than throwing on the first failure); a caller that cares about delivery
 * guarantees reads the per-kid results, this function does not retry.
 * `entry.kind` is expected to be `'application'`; a caller passing anything
 * else is a caller bug, not something this function has an opinion on. */
export async function fanOutApplicationMessage(
  groupId: string,
  senderKid: string,
  entry: ConversationLogEntry,
  roster: string[],
  opts: SendDidCommMessageOptions,
): Promise<FanOutRecipientResult[]> {
  const recipients = roster.filter(kid => kid !== senderKid)
  const body = { groupId, seq: entry.seq, epoch: entry.epoch, privateMessage: bytesToBase64url(entry.payload), at: entry.at }
  return Promise.all(recipients.map(async (kid): Promise<FanOutRecipientResult> => ({
    kid,
    result: await sendFrontDoorMessage(didOfKid(kid), T.MESSAGE_NOTIFY, body, opts),
  })))
}
