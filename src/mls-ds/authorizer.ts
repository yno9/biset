// Signature verification and DS-call boundary for the Conversation Group DS
// (mls-ds/store.ts). Parallels coordinator/mls-delivery-authorizer.ts's Self
// Group version with `identityId` dropped throughout (PLAN_biset-mls-ds.md
// §7) -- and, since the identity-blind revision, with DID resolution
// dropped too: a control message's `senderId` (or `creatorId`/
// `requesterId`/etc.) IS an Ed25519 public key (conversation-mls-ds.ts's
// `GroupLocalId`), so "does this signature verify against the pubkey the
// id itself names" is the entire proof. No resolver object, no DID
// document fetch, no credential payload -- this file has nothing left to
// depend on.
import { ed25519 } from '@noble/curves/ed25519.js'
import { hexToBytes } from '../protocol/canonical.ts'
import {
  conversationCommitSubmitSigningBytes,
  conversationDeliveriesPullSigningBytes,
  conversationGroupCreateSigningBytes,
  conversationKeyPackageCountPullSigningBytes,
  conversationKeyPackageDropSigningBytes,
  conversationKeyPackagePublishSigningBytes,
  conversationKeyPackageTakeSigningBytes,
  conversationMessageSubmitSigningBytes,
  conversationPendingRemovalsClearSigningBytes,
  conversationSelfRemoveSubmitSigningBytes,
} from '../protocol/conversation-mls-ds-signing.ts'
import type {
  ConversationCommitSubmitV1,
  ConversationDeliveriesPullV1,
  ConversationGroupCreateV1,
  ConversationKeyPackageCountPullV1,
  ConversationKeyPackageDropV1,
  ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1,
  ConversationLogEntry,
  ConversationMessageSubmitV1,
  ConversationPendingRemovalsClearV1,
  ConversationSelfRemoveSubmitV1,
} from '../protocol/conversation-mls-ds.ts'
import type { ConversationCommitResult, SqliteConversationDeliveryService } from './store.ts'

export interface ConversationDsSignatureVerifier {
  verifyGroupCreate(value: ConversationGroupCreateV1): Promise<boolean>
  verifyCommitSubmit(value: ConversationCommitSubmitV1): Promise<boolean>
  verifyKeyPackagePublish(value: ConversationKeyPackagePublishV1): Promise<boolean>
  verifyKeyPackageTake(value: ConversationKeyPackageTakeV1): Promise<boolean>
  verifySelfRemoveSubmit(value: ConversationSelfRemoveSubmitV1): Promise<boolean>
  verifyPendingRemovalsClear(value: ConversationPendingRemovalsClearV1): Promise<boolean>
  verifyDeliveriesPull(value: ConversationDeliveriesPullV1): Promise<boolean>
  verifyKeyPackageDrop(value: ConversationKeyPackageDropV1): Promise<boolean>
  verifyKeyPackageCountPull(value: ConversationKeyPackageCountPullV1): Promise<boolean>
  verifyMessageSubmit(value: ConversationMessageSubmitV1): Promise<boolean>
}

export class Ed25519ConversationDsSignatureVerifier implements ConversationDsSignatureVerifier {
  async verifyGroupCreate(value: ConversationGroupCreateV1): Promise<boolean> {
    return this.verify(value.creatorId, conversationGroupCreateSigningBytes(value), value.signature)
  }
  async verifyCommitSubmit(value: ConversationCommitSubmitV1): Promise<boolean> {
    return this.verify(value.senderId, conversationCommitSubmitSigningBytes(value), value.signature)
  }
  async verifyKeyPackagePublish(value: ConversationKeyPackagePublishV1): Promise<boolean> {
    return this.verify(value.id, conversationKeyPackagePublishSigningBytes(value), value.signature)
  }
  async verifyKeyPackageTake(value: ConversationKeyPackageTakeV1): Promise<boolean> {
    return this.verify(value.requesterId, conversationKeyPackageTakeSigningBytes(value), value.signature)
  }
  async verifySelfRemoveSubmit(value: ConversationSelfRemoveSubmitV1): Promise<boolean> {
    return this.verify(value.senderId, conversationSelfRemoveSubmitSigningBytes(value), value.signature)
  }
  async verifyPendingRemovalsClear(value: ConversationPendingRemovalsClearV1): Promise<boolean> {
    return this.verify(value.requesterId, conversationPendingRemovalsClearSigningBytes(value), value.signature)
  }
  async verifyDeliveriesPull(value: ConversationDeliveriesPullV1): Promise<boolean> {
    return this.verify(value.requesterId, conversationDeliveriesPullSigningBytes(value), value.signature)
  }
  async verifyKeyPackageDrop(value: ConversationKeyPackageDropV1): Promise<boolean> {
    return this.verify(value.id, conversationKeyPackageDropSigningBytes(value), value.signature)
  }
  async verifyKeyPackageCountPull(value: ConversationKeyPackageCountPullV1): Promise<boolean> {
    return this.verify(value.id, conversationKeyPackageCountPullSigningBytes(value), value.signature)
  }
  async verifyMessageSubmit(value: ConversationMessageSubmitV1): Promise<boolean> {
    return this.verify(value.senderId, conversationMessageSubmitSigningBytes(value), value.signature)
  }

  private verify(id: string, bytes: Uint8Array, signature: Uint8Array): boolean {
    if (signature.length !== 64) return false
    let publicKey: Uint8Array
    try {
      publicKey = hexToBytes(id)
    } catch {
      return false
    }
    return publicKey.length === 32 && ed25519.verify(signature, bytes, publicKey)
  }
}

export type ConversationGroupCreateOutcome = { ok: true; roster: string[] } | { ok: false }

export async function createConversationGroup(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationGroupCreateV1): Promise<ConversationGroupCreateOutcome> {
  if (!(await verifier.verifyGroupCreate(value))) return { ok: false }
  return { ok: true, ...ds.createGroup(value.groupId, value.creatorId) }
}

export async function submitConversationCommit(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationCommitSubmitV1): Promise<ConversationCommitResult> {
  if (!(await verifier.verifyCommitSubmit(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitCommit(value.groupId, value.senderId, value.epoch, value.commit, value.addedIds, value.removedIds, value.welcome)
}

export async function publishConversationKeyPackages(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationKeyPackagePublishV1): Promise<number | undefined> {
  if (!(await verifier.verifyKeyPackagePublish(value))) return undefined
  return ds.publishKeyPackages(value.id, value.packages)
}

export async function takeConversationKeyPackage(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationKeyPackageTakeV1): Promise<{ keyPackage: Uint8Array } | undefined> {
  if (!(await verifier.verifyKeyPackageTake(value))) return undefined
  return ds.takeKeyPackage(value.targetId)
}

export async function submitConversationSelfRemove(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationSelfRemoveSubmitV1): Promise<ConversationCommitResult> {
  if (!(await verifier.verifySelfRemoveSubmit(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitSelfRemove(value.groupId, value.senderId, value.epoch, value.proposal, value.removedId)
}

/** Returns `false` when the request is unauthorized OR the DS silently
 * no-oped it (the requester was not the group's last committer). */
export async function clearConversationPendingRemovals(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationPendingRemovalsClearV1): Promise<boolean> {
  if (!(await verifier.verifyPendingRemovalsClear(value))) return false
  ds.clearPendingRemovals(value.groupId, value.requesterId, value.clearedIds)
  return true
}

export async function pullConversationDeliveries(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationDeliveriesPullV1): Promise<ConversationLogEntry[] | undefined> {
  if (!(await verifier.verifyDeliveriesPull(value))) return undefined
  return ds.deliveriesSince(value.groupId, value.requesterId, value.afterSeq)
}

export async function dropConversationKeyPackages(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationKeyPackageDropV1): Promise<boolean> {
  if (!(await verifier.verifyKeyPackageDrop(value))) return false
  ds.dropKeyPackages(value.id)
  return true
}

export async function pullConversationKeyPackageCount(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationKeyPackageCountPullV1): Promise<number | undefined> {
  if (!(await verifier.verifyKeyPackageCountPull(value))) return undefined
  return ds.keyPackageCount(value.id)
}

export async function submitConversationMessage(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationMessageSubmitV1): Promise<ConversationCommitResult> {
  if (!(await verifier.verifyMessageSubmit(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitMessage(value.groupId, value.senderId, value.epoch, value.privateMessage)
}
