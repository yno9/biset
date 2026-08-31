// Signature verification and DS-call boundary for the Conversation Group DS
// (mls-ds/store.ts). Parallels coordinator/mls-delivery-authorizer.ts's Self
// Group version with `identityId` dropped throughout (PLAN_biset-mls-ds.md
// §7): a control message's sender is authenticated purely by resolving
// `senderKid`'s own device key (didOfKid gives the DID to resolve against --
// no separate identityId parameter needed to know which DID that is).
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  conversationCommitSubmitSigningBytes,
  conversationDeliveriesPullSigningBytes,
  conversationExternalCommitSubmitSigningBytes,
  conversationGroupCreateSigningBytes,
  conversationGroupInfoPullSigningBytes,
  conversationGroupsForPullSigningBytes,
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
  ConversationExternalCommitSubmitV1,
  ConversationGroupCreateV1,
  ConversationGroupInfoPullV1,
  ConversationGroupsForPullV1,
  ConversationKeyPackageCountPullV1,
  ConversationKeyPackageDropV1,
  ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1,
  ConversationLogEntry,
  ConversationMessageSubmitV1,
  ConversationPendingRemovalsClearV1,
  ConversationSelfRemoveSubmitV1,
} from '../protocol/conversation-mls-ds.ts'
import type { ConversationCommitResult, ConversationGroupInfoAnswer, SqliteConversationDeliveryService } from './store.ts'

/** Public-key lookup boundary for signed Conversation DS control requests.
 * No `identityId` parameter (contrast coordinator/mls-delivery-authorizer.ts's
 * DeviceSigningPublicKeyResolver) -- the implementation resolves whichever
 * DID `signingKeyId` (a `did#fragment`) names for itself. */
export interface ConversationDeviceSigningPublicKeyResolver {
  resolveEd25519PublicKey(signingKeyId: string, deviceCredential: Uint8Array | undefined): Promise<Uint8Array | undefined>
}

export interface ConversationDsSignatureVerifier {
  verifyGroupCreate(value: ConversationGroupCreateV1): Promise<boolean>
  verifyCommitSubmit(value: ConversationCommitSubmitV1): Promise<boolean>
  verifyExternalCommitSubmit(value: ConversationExternalCommitSubmitV1): Promise<boolean>
  verifyGroupInfoPull(value: ConversationGroupInfoPullV1): Promise<boolean>
  verifyKeyPackagePublish(value: ConversationKeyPackagePublishV1): Promise<boolean>
  verifyKeyPackageTake(value: ConversationKeyPackageTakeV1): Promise<boolean>
  verifySelfRemoveSubmit(value: ConversationSelfRemoveSubmitV1): Promise<boolean>
  verifyPendingRemovalsClear(value: ConversationPendingRemovalsClearV1): Promise<boolean>
  verifyDeliveriesPull(value: ConversationDeliveriesPullV1): Promise<boolean>
  verifyKeyPackageDrop(value: ConversationKeyPackageDropV1): Promise<boolean>
  verifyKeyPackageCountPull(value: ConversationKeyPackageCountPullV1): Promise<boolean>
  verifyGroupsForPull(value: ConversationGroupsForPullV1): Promise<boolean>
  verifyMessageSubmit(value: ConversationMessageSubmitV1): Promise<boolean>
}

export class Ed25519ConversationDsSignatureVerifier implements ConversationDsSignatureVerifier {
  constructor(private readonly keys: ConversationDeviceSigningPublicKeyResolver) {}

  verifyGroupCreate(value: ConversationGroupCreateV1): Promise<boolean> {
    return this.verify(value.creatorKid, value.deviceCredential, conversationGroupCreateSigningBytes(value), value.signature)
  }
  verifyCommitSubmit(value: ConversationCommitSubmitV1): Promise<boolean> {
    return this.verify(value.senderKid, value.deviceCredential, conversationCommitSubmitSigningBytes(value), value.signature)
  }
  verifyExternalCommitSubmit(value: ConversationExternalCommitSubmitV1): Promise<boolean> {
    return this.verify(value.senderKid, value.deviceCredential, conversationExternalCommitSubmitSigningBytes(value), value.signature)
  }
  verifyGroupInfoPull(value: ConversationGroupInfoPullV1): Promise<boolean> {
    return this.verify(value.requesterKid, value.deviceCredential, conversationGroupInfoPullSigningBytes(value), value.signature)
  }
  verifyKeyPackagePublish(value: ConversationKeyPackagePublishV1): Promise<boolean> {
    return this.verify(value.kid, value.deviceCredential, conversationKeyPackagePublishSigningBytes(value), value.signature)
  }
  verifyKeyPackageTake(value: ConversationKeyPackageTakeV1): Promise<boolean> {
    return this.verify(value.requesterKid, value.deviceCredential, conversationKeyPackageTakeSigningBytes(value), value.signature)
  }
  verifySelfRemoveSubmit(value: ConversationSelfRemoveSubmitV1): Promise<boolean> {
    return this.verify(value.senderKid, value.deviceCredential, conversationSelfRemoveSubmitSigningBytes(value), value.signature)
  }
  verifyPendingRemovalsClear(value: ConversationPendingRemovalsClearV1): Promise<boolean> {
    return this.verify(value.requesterKid, value.deviceCredential, conversationPendingRemovalsClearSigningBytes(value), value.signature)
  }
  verifyDeliveriesPull(value: ConversationDeliveriesPullV1): Promise<boolean> {
    return this.verify(value.requesterKid, value.deviceCredential, conversationDeliveriesPullSigningBytes(value), value.signature)
  }
  verifyKeyPackageDrop(value: ConversationKeyPackageDropV1): Promise<boolean> {
    return this.verify(value.kid, value.deviceCredential, conversationKeyPackageDropSigningBytes(value), value.signature)
  }
  verifyKeyPackageCountPull(value: ConversationKeyPackageCountPullV1): Promise<boolean> {
    return this.verify(value.kid, value.deviceCredential, conversationKeyPackageCountPullSigningBytes(value), value.signature)
  }
  verifyGroupsForPull(value: ConversationGroupsForPullV1): Promise<boolean> {
    return this.verify(value.requesterKid, value.deviceCredential, conversationGroupsForPullSigningBytes(value), value.signature)
  }
  verifyMessageSubmit(value: ConversationMessageSubmitV1): Promise<boolean> {
    return this.verify(value.senderKid, value.deviceCredential, conversationMessageSubmitSigningBytes(value), value.signature)
  }

  private async verify(kid: string, credential: Uint8Array | undefined, bytes: Uint8Array, signature: Uint8Array): Promise<boolean> {
    if (signature.length !== 64) return false
    const publicKey = await this.keys.resolveEd25519PublicKey(kid, credential)
    return publicKey !== undefined && publicKey.length === 32 && ed25519.verify(signature, bytes, publicKey)
  }
}

export type ConversationGroupCreateOutcome = { ok: true; roster: string[] } | { ok: false }

export async function createConversationGroup(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationGroupCreateV1): Promise<ConversationGroupCreateOutcome> {
  if (!(await verifier.verifyGroupCreate(value))) return { ok: false }
  return { ok: true, ...ds.createGroup(value.groupId, value.creatorKid, value.roster) }
}

export async function submitConversationCommit(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationCommitSubmitV1): Promise<ConversationCommitResult> {
  if (!(await verifier.verifyCommitSubmit(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitCommit(value.groupId, value.senderKid, value.epoch, value.commit, value.roster, value.welcome, value.welcomeTo, value.groupInfo)
}

export async function submitConversationExternalCommit(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationExternalCommitSubmitV1): Promise<ConversationCommitResult> {
  if (!(await verifier.verifyExternalCommitSubmit(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitExternalCommit(value.groupId, value.senderKid, value.epoch, value.commit, value.groupInfo)
}

export type ConversationGroupInfoPullResult = { ok: true; answer: ConversationGroupInfoAnswer } | { ok: false }

export async function pullConversationGroupInfo(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationGroupInfoPullV1): Promise<ConversationGroupInfoPullResult> {
  if (!(await verifier.verifyGroupInfoPull(value))) return { ok: false }
  return { ok: true, answer: ds.groupInfoFor(value.groupId) ?? { pendingRemovals: [] } }
}

export async function publishConversationKeyPackages(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationKeyPackagePublishV1): Promise<number | undefined> {
  if (!(await verifier.verifyKeyPackagePublish(value))) return undefined
  return ds.publishKeyPackages(value.kid, value.packages)
}

export async function takeConversationKeyPackage(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationKeyPackageTakeV1): Promise<{ keyPackage: Uint8Array } | undefined> {
  if (!(await verifier.verifyKeyPackageTake(value))) return undefined
  return ds.takeKeyPackage(value.targetKid)
}

export async function submitConversationSelfRemove(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationSelfRemoveSubmitV1): Promise<ConversationCommitResult> {
  if (!(await verifier.verifySelfRemoveSubmit(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitSelfRemove(value.groupId, value.senderKid, value.epoch, value.proposal, value.removedKid)
}

/** Returns `false` when the request is unauthorized OR the DS silently
 * no-oped it (the requester was not the group's last committer). */
export async function clearConversationPendingRemovals(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationPendingRemovalsClearV1): Promise<boolean> {
  if (!(await verifier.verifyPendingRemovalsClear(value))) return false
  ds.clearPendingRemovals(value.groupId, value.requesterKid, value.clearedKids)
  return true
}

export async function pullConversationDeliveries(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationDeliveriesPullV1): Promise<ConversationLogEntry[] | undefined> {
  if (!(await verifier.verifyDeliveriesPull(value))) return undefined
  return ds.deliveriesSince(value.groupId, value.requesterKid, value.afterSeq)
}

export async function dropConversationKeyPackages(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationKeyPackageDropV1): Promise<boolean> {
  if (!(await verifier.verifyKeyPackageDrop(value))) return false
  ds.dropKeyPackages(value.kid)
  return true
}

export async function pullConversationKeyPackageCount(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationKeyPackageCountPullV1): Promise<number | undefined> {
  if (!(await verifier.verifyKeyPackageCountPull(value))) return undefined
  return ds.keyPackageCount(value.kid)
}

export async function pullConversationGroupsFor(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationGroupsForPullV1): Promise<Array<{ groupId: string; epoch: bigint }> | undefined> {
  if (!(await verifier.verifyGroupsForPull(value))) return undefined
  return ds.groupsFor(value.requesterKid)
}

export async function submitConversationMessage(ds: SqliteConversationDeliveryService, verifier: ConversationDsSignatureVerifier, value: ConversationMessageSubmitV1): Promise<ConversationCommitResult> {
  if (!(await verifier.verifyMessageSubmit(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitMessage(value.groupId, value.senderKid, value.epoch, value.privateMessage)
}
