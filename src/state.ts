import type { InboxSummary } from './types.ts'

// processedMessages/ProcessedMessage/ThreadGroup/messageKey/groupMessages/
// latestGroup all live in mail/message-view.ts now, not here -- that file's
// own header explains why (it deliberately kept src.bak/state.ts's exact
// field names/snake_case for this same reason: less diff for ported UI
// code). Redefining them here too would be the exact "same concept, two
// divergent implementations" this codebase's own standing rule forbids;
// resolved by deleting the old duplicate rather than keeping both (per user
// direction, 2026-08-25: code conflicting with the current design gets
// deleted, not kept alongside it).
//
// This also means the OLD reactions/group_id/group_name/edited fields
// (DeltaChat/RFC 9078/MLS-group features, all out of this rewrite's current
// scope) aren't available on a message here -- ported UI code that reads
// them needs those reads removed, the same way message-view.ts's own header
// already scoped them out.
export {
  processedMessages,
  messageKey,
  groupMessages,
  latestGroup,
  type ProcessedMessage,
  type ThreadGroup,
} from './mail/message-view.ts'

export let focusedThreadKey: string | null = null
export let lastTs = 0
export let notifEnabled = false
export let isFirstFetch = true

export function setFocusedThreadKey(k: string | null): void { focusedThreadKey = k }
export function setLastTs(ts: number): void { lastTs = ts }
export function setNotifEnabled(v: boolean): void { notifEnabled = v }
export function setIsFirstFetch(v: boolean): void { isFirstFetch = v }

export let lastLeftInboxes: InboxSummary[] = []
export function setLastLeftInboxes(v: InboxSummary[]): void { lastLeftInboxes = v }
