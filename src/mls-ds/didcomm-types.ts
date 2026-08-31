// Message Type URIs for the Conversation Group DS DIDComm binding
// (docs/protocols/mls-ds-1.0.md), same PING/BASIC_MESSAGE-style constant
// pattern as trust-ping.ts/basicmessage.ts.
export const PIURI = 'https://biset.md/mls-ds/1.0'

export const GROUP_CREATE = `${PIURI}/group-create`
export const COMMIT_SUBMIT = `${PIURI}/commit-submit`
export const COMMIT_SUBMIT_EXTERNAL = `${PIURI}/commit-submit-external`
export const GROUP_INFO_PULL = `${PIURI}/group-info-pull`
export const GROUP_INFO = `${PIURI}/group-info`
export const KEYPACKAGE_PUBLISH = `${PIURI}/keypackage-publish`
export const KEYPACKAGE_TAKE = `${PIURI}/keypackage-take`
export const KEYPACKAGE_TAKEN = `${PIURI}/keypackage-taken`
export const KEYPACKAGE_DROP = `${PIURI}/keypackage-drop`
export const KEYPACKAGE_COUNT_PULL = `${PIURI}/keypackage-count-pull`
export const KEYPACKAGE_COUNT = `${PIURI}/keypackage-count`
export const GROUPS_FOR_PULL = `${PIURI}/groups-for-pull`
export const GROUPS_FOR = `${PIURI}/groups-for`
export const SELF_REMOVE_SUBMIT = `${PIURI}/self-remove-submit`
export const PENDING_REMOVALS_CLEAR = `${PIURI}/pending-removals-clear`
export const DELIVERIES_PULL = `${PIURI}/deliveries-pull`
export const DELIVERIES = `${PIURI}/deliveries`
export const MESSAGE_SUBMIT = `${PIURI}/message-submit`
export const MESSAGE_NOTIFY = `${PIURI}/message-notify`

const REQUEST_TYPES = new Set([
  GROUP_CREATE, COMMIT_SUBMIT, COMMIT_SUBMIT_EXTERNAL, GROUP_INFO_PULL, KEYPACKAGE_PUBLISH,
  KEYPACKAGE_TAKE, KEYPACKAGE_DROP, KEYPACKAGE_COUNT_PULL, GROUPS_FOR_PULL, SELF_REMOVE_SUBMIT,
  PENDING_REMOVALS_CLEAR, DELIVERIES_PULL, MESSAGE_SUBMIT,
])

/** Whether a DIDComm plaintext's `type` is one this DS handles as a
 * request (mls-ds-1.0.md §3-5) -- everything else (including this
 * protocol's own response types) is not this handler's concern. */
export function isConversationDsRequest(type: string): boolean { return REQUEST_TYPES.has(type) }
