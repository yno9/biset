// Canonical signing-bytes builders for Conversation Group DS control
// messages (conversation-mls-ds.ts). Field-for-field the same pattern as
// signing.ts's Self Group builders, minus `identityId` (PLAN_biset-mls-ds.md
// §7) and under a distinct label namespace (`biset/conversation-mls-*` vs
// `biset/mls-*`) so a signature can never be replayed across the two DSs.
import { bytesToBase64url, canonicalBytes } from './canonical.ts'
import type {
  ConversationCommitSubmitV1,
  ConversationDeliveriesPullV1,
  ConversationGroupCreateV1,
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
    creatorId: value.creatorId,
    createdAt: value.createdAt,
  })
}

export function conversationCommitSubmitSigningBytes(value: Omit<ConversationCommitSubmitV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-commit-submit/v1',
    version: value.version,
    groupId: value.groupId,
    senderId: value.senderId,
    epoch: value.epoch,
    commit: bytesToBase64url(value.commit),
    ...(value.addedIds === undefined ? {} : { addedIds: value.addedIds }),
    ...(value.removedIds === undefined ? {} : { removedIds: value.removedIds }),
    ...(value.welcome === undefined ? {} : { welcome: bytesToBase64url(value.welcome) }),
    submittedAt: value.submittedAt,
  })
}

export function conversationKeyPackagePublishSigningBytes(value: Omit<ConversationKeyPackagePublishV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-keypackage-publish/v1',
    version: value.version,
    id: value.id,
    packages: value.packages.map(bytesToBase64url),
    publishedAt: value.publishedAt,
  })
}

export function conversationKeyPackageTakeSigningBytes(value: Omit<ConversationKeyPackageTakeV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-keypackage-take/v1',
    version: value.version,
    requesterId: value.requesterId,
    targetId: value.targetId,
    requestedAt: value.requestedAt,
  })
}

export function conversationSelfRemoveSubmitSigningBytes(value: Omit<ConversationSelfRemoveSubmitV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-self-remove-submit/v1',
    version: value.version,
    groupId: value.groupId,
    senderId: value.senderId,
    epoch: value.epoch,
    proposal: bytesToBase64url(value.proposal),
    removedId: value.removedId,
    submittedAt: value.submittedAt,
  })
}

export function conversationPendingRemovalsClearSigningBytes(value: Omit<ConversationPendingRemovalsClearV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-pending-removals-clear/v1',
    version: value.version,
    groupId: value.groupId,
    requesterId: value.requesterId,
    clearedIds: value.clearedIds,
    clearedAt: value.clearedAt,
  })
}

export function conversationDeliveriesPullSigningBytes(value: Omit<ConversationDeliveriesPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-deliveries-pull/v1',
    version: value.version,
    groupId: value.groupId,
    requesterId: value.requesterId,
    afterSeq: value.afterSeq,
    requestedAt: value.requestedAt,
  })
}

export function conversationKeyPackageDropSigningBytes(value: Omit<ConversationKeyPackageDropV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-keypackage-drop/v1',
    version: value.version,
    id: value.id,
    droppedAt: value.droppedAt,
  })
}

export function conversationKeyPackageCountPullSigningBytes(value: Omit<ConversationKeyPackageCountPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-keypackage-count-pull/v1',
    version: value.version,
    id: value.id,
    requestedAt: value.requestedAt,
  })
}

export function conversationMessageSubmitSigningBytes(value: Omit<ConversationMessageSubmitV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/conversation-mls-message-submit/v1',
    version: value.version,
    groupId: value.groupId,
    senderId: value.senderId,
    epoch: value.epoch,
    privateMessage: bytesToBase64url(value.privateMessage),
    submittedAt: value.submittedAt,
  })
}
