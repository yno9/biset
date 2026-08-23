// Signature verification for the MLS self-group DS (mls-delivery-store.ts).
// Each control message is verified against the SENDER'S OWN device key,
// resolved by DID (DeviceSigningPublicKeyResolver) rather than through
// TrustedDeviceRoster — the same reason mls-delivery-store.ts's own roster
// is kept independent of that roster: a commit's sender must be
// authenticated before the DS can even ask whether it thinks that kid is
// currently in the group, and TrustedDeviceRoster only reflects commits this
// DS already accepted and a producer already turned into a signed install.
// This is the same "resolve the credential kid, check the signature" shape
// the Authentication Service uses (mls/webvh-authentication-service.ts),
// applied to transport-layer control rather than the MLS credential itself.
import { ed25519 } from '@noble/curves/ed25519.js'
import type { DeviceSigningPublicKeyResolver } from '../identity/ed25519-device-control-verifier.ts'
import { didOfKid } from '../../protocol/ids.ts'
import {
  mlsCommitSubmissionSigningBytes,
  mlsDeliveriesPullSigningBytes,
  mlsExternalCommitSubmissionSigningBytes,
  mlsGroupCreationSigningBytes,
  mlsGroupInfoPullSigningBytes,
  mlsGroupsForPullSigningBytes,
  mlsKeyPackageCountPullSigningBytes,
  mlsKeyPackageDropSigningBytes,
  mlsKeyPackagePublishSigningBytes,
  mlsKeyPackageTakeSigningBytes,
  mlsPendingRemovalsClearSigningBytes,
  mlsSelfRemoveSubmissionSigningBytes,
} from '../../protocol/signing.ts'
import type {
  MlsCommitSubmissionV1,
  MlsDeliveriesPullV1,
  MlsExternalCommitSubmissionV1,
  MlsGroupCreationV1,
  MlsGroupInfoPullV1,
  MlsGroupsForPullV1,
  MlsKeyPackageCountPullV1,
  MlsKeyPackageDropV1,
  MlsKeyPackagePublishV1,
  MlsKeyPackageTakeV1,
  MlsPendingRemovalsClearV1,
  MlsSelfRemoveSubmissionV1,
} from '../../protocol/mls-ds.ts'
import type { MlsCommitResult, MlsGroupInfoAnswer, MlsLogEntry, SqliteMlsDeliveryService } from './mls-delivery-store.ts'

export interface MlsDsSignatureVerifier {
  verifyGroupCreation(value: MlsGroupCreationV1): Promise<boolean>
  verifyCommitSubmission(value: MlsCommitSubmissionV1): Promise<boolean>
  verifyExternalCommitSubmission(value: MlsExternalCommitSubmissionV1): Promise<boolean>
  verifyGroupInfoPull(value: MlsGroupInfoPullV1): Promise<boolean>
  verifyKeyPackagePublish(value: MlsKeyPackagePublishV1): Promise<boolean>
  verifyKeyPackageTake(value: MlsKeyPackageTakeV1): Promise<boolean>
  verifySelfRemoveSubmission(value: MlsSelfRemoveSubmissionV1): Promise<boolean>
  verifyPendingRemovalsClear(value: MlsPendingRemovalsClearV1): Promise<boolean>
  verifyDeliveriesPull(value: MlsDeliveriesPullV1): Promise<boolean>
  verifyKeyPackageDrop(value: MlsKeyPackageDropV1): Promise<boolean>
  verifyKeyPackageCountPull(value: MlsKeyPackageCountPullV1): Promise<boolean>
  verifyGroupsForPull(value: MlsGroupsForPullV1): Promise<boolean>
}

export class Ed25519MlsDsSignatureVerifier implements MlsDsSignatureVerifier {
  constructor(private readonly keys: DeviceSigningPublicKeyResolver) {}

  verifyGroupCreation(value: MlsGroupCreationV1): Promise<boolean> {
    return this.verify(value.creatorKid, mlsGroupCreationSigningBytes(value), value.signature)
  }
  verifyCommitSubmission(value: MlsCommitSubmissionV1): Promise<boolean> {
    return this.verify(value.senderKid, mlsCommitSubmissionSigningBytes(value), value.signature)
  }
  verifyExternalCommitSubmission(value: MlsExternalCommitSubmissionV1): Promise<boolean> {
    return this.verify(value.senderKid, mlsExternalCommitSubmissionSigningBytes(value), value.signature)
  }
  verifyGroupInfoPull(value: MlsGroupInfoPullV1): Promise<boolean> {
    return this.verify(value.requesterKid, mlsGroupInfoPullSigningBytes(value), value.signature)
  }
  verifyKeyPackagePublish(value: MlsKeyPackagePublishV1): Promise<boolean> {
    return this.verify(value.kid, mlsKeyPackagePublishSigningBytes(value), value.signature)
  }
  verifyKeyPackageTake(value: MlsKeyPackageTakeV1): Promise<boolean> {
    return this.verify(value.requesterKid, mlsKeyPackageTakeSigningBytes(value), value.signature)
  }
  verifySelfRemoveSubmission(value: MlsSelfRemoveSubmissionV1): Promise<boolean> {
    return this.verify(value.senderKid, mlsSelfRemoveSubmissionSigningBytes(value), value.signature)
  }
  verifyPendingRemovalsClear(value: MlsPendingRemovalsClearV1): Promise<boolean> {
    return this.verify(value.requesterKid, mlsPendingRemovalsClearSigningBytes(value), value.signature)
  }
  verifyDeliveriesPull(value: MlsDeliveriesPullV1): Promise<boolean> {
    return this.verify(value.requesterKid, mlsDeliveriesPullSigningBytes(value), value.signature)
  }
  verifyKeyPackageDrop(value: MlsKeyPackageDropV1): Promise<boolean> {
    return this.verify(value.kid, mlsKeyPackageDropSigningBytes(value), value.signature)
  }
  verifyKeyPackageCountPull(value: MlsKeyPackageCountPullV1): Promise<boolean> {
    return this.verify(value.kid, mlsKeyPackageCountPullSigningBytes(value), value.signature)
  }
  verifyGroupsForPull(value: MlsGroupsForPullV1): Promise<boolean> {
    return this.verify(value.requesterKid, mlsGroupsForPullSigningBytes(value), value.signature)
  }

  private async verify(kid: string, bytes: Uint8Array, signature: Uint8Array): Promise<boolean> {
    if (signature.length !== 64) return false
    const publicKey = await this.keys.resolveEd25519PublicKey(kid)
    return publicKey !== undefined && publicKey.length === 32 && ed25519.verify(signature, bytes, publicKey)
  }
}

export type MlsGroupCreationOutcome = { ok: true; roster: string[] } | { ok: false }

export async function createMlsGroup(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsGroupCreationV1): Promise<MlsGroupCreationOutcome> {
  if (!(await verifier.verifyGroupCreation(value))) return { ok: false }
  return { ok: true, ...ds.createGroup(value.groupId, value.identityId, value.creatorKid, value.roster) }
}

export async function submitMlsCommit(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsCommitSubmissionV1): Promise<MlsCommitResult> {
  if (!(await verifier.verifyCommitSubmission(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitCommit(value.groupId, value.senderKid, value.epoch, value.commit, value.roster, value.welcome, value.welcomeTo, value.groupInfo)
}

/**
 * `groupInfoFor`/`submitExternalCommit` are gated on `identityId`, not
 * `roster.has(kid)` — a joining device is by definition not yet in the
 * roster (mls-delivery-store.ts's own comment on why). The signature proves
 * `senderKid`'s owner controls that key; this extra `didOfKid` check is what
 * stops that owner from pairing a validly-signed message with SOMEONE ELSE'S
 * `identityId` to read or join a self-group that is not theirs.
 */
export async function submitMlsExternalCommit(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsExternalCommitSubmissionV1): Promise<MlsCommitResult> {
  if (didOfKid(value.senderKid) !== value.identityId) return { ok: false, reason: 'unauthorized', epoch: '0' }
  if (!(await verifier.verifyExternalCommitSubmission(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitExternalCommit(value.groupId, value.identityId, value.senderKid, value.epoch, value.commit, value.groupInfo)
}

export type MlsGroupInfoPullResult = { ok: true; answer: MlsGroupInfoAnswer } | { ok: false }

/**
 * `ok: false` means unauthorized (bad signature, or `requesterKid` does not
 * belong to `identityId`); it is NOT what a nonexistent group returns. A
 * device's very first join attempt asks for a GroupInfo before any group
 * has been created, and that is exactly the ordinary "fall back to
 * createSelfGroup" case (self-group.ts's `joinSelfGroupExternally`) — it
 * must come back as an authorized empty answer (`{ pendingRemovals: [] }`),
 * never as a 403 indistinguishable from an actual authorization failure.
 */
export async function pullMlsGroupInfo(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsGroupInfoPullV1): Promise<MlsGroupInfoPullResult> {
  if (didOfKid(value.requesterKid) !== value.identityId) return { ok: false }
  if (!(await verifier.verifyGroupInfoPull(value))) return { ok: false }
  return { ok: true, answer: ds.groupInfoFor(value.groupId, value.identityId) ?? { pendingRemovals: [] } }
}

export async function publishMlsKeyPackages(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsKeyPackagePublishV1): Promise<number | undefined> {
  if (!(await verifier.verifyKeyPackagePublish(value))) return undefined
  return ds.publishKeyPackages(value.kid, value.identityId, value.packages)
}

/**
 * `isLive` decides which of the identity's published key-package kids are
 * still real devices (typically `TrustedDeviceRoster.isTrustedDevice`) — the
 * DS itself has no notion of device liveness beyond what was last committed.
 */
export async function takeMlsKeyPackages(
  ds: SqliteMlsDeliveryService,
  verifier: MlsDsSignatureVerifier,
  value: MlsKeyPackageTakeV1,
  isLive: (kid: string) => Promise<boolean>,
): Promise<Array<{ kid: string; keyPackage: Uint8Array }> | undefined> {
  if (!(await verifier.verifyKeyPackageTake(value))) return undefined
  return ds.takeKeyPackages(value.identityId, isLive)
}

export async function submitMlsSelfRemove(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsSelfRemoveSubmissionV1): Promise<MlsCommitResult> {
  if (!(await verifier.verifySelfRemoveSubmission(value))) return { ok: false, reason: 'unauthorized', epoch: '0' }
  return ds.submitSelfRemove(value.groupId, value.senderKid, value.epoch, value.proposal, value.removedKid)
}

/** Returns `false` when the request is unauthorized OR the DS silently no-oped it
 * (the requester was not the group's last committer — `SqliteMlsDeliveryService`'s own rule). */
export async function clearMlsPendingRemovals(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsPendingRemovalsClearV1): Promise<boolean> {
  if (!(await verifier.verifyPendingRemovalsClear(value))) return false
  ds.clearPendingRemovals(value.groupId, value.requesterKid, value.clearedKids)
  return true
}

export async function pullMlsDeliveries(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsDeliveriesPullV1): Promise<MlsLogEntry[] | undefined> {
  if (!(await verifier.verifyDeliveriesPull(value))) return undefined
  return ds.deliveriesSince(value.groupId, value.requesterKid, value.afterSeq)
}

export async function dropMlsKeyPackages(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsKeyPackageDropV1): Promise<boolean> {
  if (!(await verifier.verifyKeyPackageDrop(value))) return false
  ds.dropKeyPackages(value.kid)
  return true
}

export async function pullMlsKeyPackageCount(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsKeyPackageCountPullV1): Promise<number | undefined> {
  if (!(await verifier.verifyKeyPackageCountPull(value))) return undefined
  return ds.keyPackageCount(value.kid)
}

export async function pullMlsGroupsFor(ds: SqliteMlsDeliveryService, verifier: MlsDsSignatureVerifier, value: MlsGroupsForPullV1): Promise<Array<{ groupId: string; epoch: bigint }> | undefined> {
  if (!(await verifier.verifyGroupsForPull(value))) return undefined
  return ds.groupsFor(value.requesterKid)
}
