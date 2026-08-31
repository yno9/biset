// Canonical signing-bytes builders for Conversation Group DS control
// messages (conversation-mls-ds.ts). Field-for-field the same pattern as
// signing.ts's Self Group builders, minus `identityId` (PLAN_biset-mls-ds.md
// §7) and under a distinct label namespace (`biset/conversation-mls-*` vs
// `biset/mls-*`) so a signature can never be replayed across the two DSs.
import { bytesToBase64url, canonicalBytes } from './canonical.ts'
import type {
  ConversationCommitSubmitV1,
  ConversationDeliveriesPullV1,
  ConversationExternalCommitSubmitV1,
  ConversationGroupCreateV1,
  ConversationGroupInfoPullV1,
  ConversationGroupsForPullV1,
  ConversationKeyPackageCountPullV1,
  ConversationKeyPackageDropV1,
  ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1,
  ConversationMessageSubmitV1,
  ConversationPendingRemovalsClearV1,
  ConversationSelfRemoveSubmitV1,
} from './conversation-mls-ds.ts'

export function conversationGroupCreateSigningBytes(value: Omit<ConversationGroupCreateV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-group-create/v1',
    version: value.version,
    groupId: value.groupId,
    creatorKid: value.creatorKid,
    roster: value.roster,
    createdAt: value.createdAt,
  })
}

export function conversationCommitSubmitSigningBytes(value: Omit<ConversationCommitSubmitV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-commit-submit/v1',
    version: value.version,
    groupId: value.groupId,
    senderKid: value.senderKid,
    epoch: value.epoch,
    commit: bytesToBase64url(value.commit),
    roster: value.roster,
    ...(value.welcome === undefined ? {} : { welcome: bytesToBase64url(value.welcome) }),
    ...(value.welcomeTo === undefined ? {} : { welcomeTo: value.welcomeTo }),
    ...(value.groupInfo === undefined ? {} : { groupInfo: bytesToBase64url(value.groupInfo) }),
    submittedAt: value.submittedAt,
  })
}

export function conversationExternalCommitSubmitSigningBytes(value: Omit<ConversationExternalCommitSubmitV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-external-commit-submit/v1',
    version: value.version,
    groupId: value.groupId,
    senderKid: value.senderKid,
    epoch: value.epoch,
    commit: bytesToBase64url(value.commit),
    groupInfo: bytesToBase64url(value.groupInfo),
    submittedAt: value.submittedAt,
  })
}

export function conversationGroupInfoPullSigningBytes(value: Omit<ConversationGroupInfoPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-group-info-pull/v1',
    version: value.version,
    groupId: value.groupId,
    requesterKid: value.requesterKid,
    requestedAt: value.requestedAt,
  })
}

export function conversationKeyPackagePublishSigningBytes(value: Omit<ConversationKeyPackagePublishV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-keypackage-publish/v1',
    version: value.version,
    kid: value.kid,
    packages: value.packages.map(bytesToBase64url),
    publishedAt: value.publishedAt,
  })
}

export function conversationKeyPackageTakeSigningBytes(value: Omit<ConversationKeyPackageTakeV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-keypackage-take/v1',
    version: value.version,
    requesterKid: value.requesterKid,
    targetKid: value.targetKid,
    requestedAt: value.requestedAt,
  })
}

export function conversationSelfRemoveSubmitSigningBytes(value: Omit<ConversationSelfRemoveSubmitV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-self-remove-submit/v1',
    version: value.version,
    groupId: value.groupId,
    senderKid: value.senderKid,
    epoch: value.epoch,
    proposal: bytesToBase64url(value.proposal),
    removedKid: value.removedKid,
    submittedAt: value.submittedAt,
  })
}

export function conversationPendingRemovalsClearSigningBytes(value: Omit<ConversationPendingRemovalsClearV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-pending-removals-clear/v1',
    version: value.version,
    groupId: value.groupId,
    requesterKid: value.requesterKid,
    clearedKids: value.clearedKids,
    clearedAt: value.clearedAt,
  })
}

export function conversationDeliveriesPullSigningBytes(value: Omit<ConversationDeliveriesPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-deliveries-pull/v1',
    version: value.version,
    groupId: value.groupId,
    requesterKid: value.requesterKid,
    afterSeq: value.afterSeq,
    requestedAt: value.requestedAt,
  })
}

export function conversationKeyPackageDropSigningBytes(value: Omit<ConversationKeyPackageDropV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-keypackage-drop/v1',
    version: value.version,
    kid: value.kid,
    droppedAt: value.droppedAt,
  })
}

export function conversationKeyPackageCountPullSigningBytes(value: Omit<ConversationKeyPackageCountPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-keypackage-count-pull/v1',
    version: value.version,
    kid: value.kid,
    requestedAt: value.requestedAt,
  })
}

export function conversationGroupsForPullSigningBytes(value: Omit<ConversationGroupsForPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-groups-for-pull/v1',
    version: value.version,
    requesterKid: value.requesterKid,
    requestedAt: value.requestedAt,
  })
}

export function conversationMessageSubmitSigningBytes(value: Omit<ConversationMessageSubmitV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-message-submit/v1',
    version: value.version,
    groupId: value.groupId,
    senderKid: value.senderKid,
    epoch: value.epoch,
    privateMessage: bytesToBase64url(value.privateMessage),
    submittedAt: value.submittedAt,
  })
}
