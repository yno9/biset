import { bytesToBase64url, canonicalBytes } from './canonical.ts'
import type { IngressAckV1, IngressPullV1 } from './ingress.ts'
import type { MailSubmissionRequestV1 } from './mail-submission.ts'
import type { RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1, VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryPullV1 } from './vault.ts'
import type {
  MlsCommitSubmissionV1, MlsDeliveriesPullV1, MlsExternalCommitSubmissionV1, MlsGroupCreationV1, MlsGroupInfoPullV1,
  MlsGroupsForPullV1, MlsKeyPackageCountPullV1, MlsKeyPackageDropV1, MlsKeyPackagePublishV1, MlsKeyPackageTakeV1,
  MlsPendingRemovalsClearV1, MlsSelfRemoveSubmissionV1,
} from './mls-ds.ts'

/**
 * Canonical bytes for device-control signatures. These functions omit only
 * `signature`; every routing, identity, expiry, and payload-binding field is
 * authenticated. They are shared by client signing and core verification.
 */
export function ingressAckSigningBytes(ack: Omit<IngressAckV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/ingress-ack/v1',
    version: ack.version,
    ingressId: ack.ingressId,
    protectedPayloadHash: bytesToBase64url(ack.protectedPayloadHash),
    recipientDeviceId: ack.recipientDeviceId,
    vaultEventId: ack.vaultEventId,
    checkpointId: ack.checkpointId,
    ackedAt: ack.ackedAt,
  })
}

export function ingressPullSigningBytes(pull: Omit<IngressPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/ingress-pull/v1',
    version: pull.version,
    identityId: pull.identityId,
    recipientDeviceId: pull.recipientDeviceId,
    requestedAt: pull.requestedAt,
  })
}

export function vaultDeliveryAckSigningBytes(ack: Omit<VaultDeliveryAckV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault-delivery-ack/v1',
    version: ack.version,
    identityId: ack.identityId,
    seq: ack.seq,
    payloadHash: bytesToBase64url(ack.payloadHash),
    recipientDeviceId: ack.recipientDeviceId,
    checkpointId: ack.checkpointId,
    ackedAt: ack.ackedAt,
  })
}

export function vaultDeliveryAppendSigningBytes(append: Omit<VaultDeliveryAppendV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault-delivery-append/v1',
    version: append.version,
    identityId: append.identityId,
    appendId: append.appendId,
    payloadHash: bytesToBase64url(append.payloadHash),
    senderDeviceId: append.senderDeviceId,
    sentAt: append.sentAt,
  })
}

export function vaultDeliveryPullSigningBytes(pull: Omit<VaultDeliveryPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault-delivery-pull/v1',
    version: pull.version,
    identityId: pull.identityId,
    recipientDeviceId: pull.recipientDeviceId,
    after: pull.after,
    requestedAt: pull.requestedAt,
  })
}

export function mailSubmissionSigningBytes(request: Omit<MailSubmissionRequestV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mail-submission/v1',
    version: request.version,
    identityId: request.identityId,
    deviceId: request.deviceId,
    mailFrom: request.mailFrom,
    rcptTo: request.rcptTo,
    rawRfc5322: bytesToBase64url(request.rawRfc5322),
    submittedAt: request.submittedAt,
  })
}

export function restoreRequestSigningBytes(request: Omit<RestoreRequestV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/restore-request/v1',
    version: request.version,
    requestId: request.requestId,
    identityId: request.identityId,
    requesterDeviceId: request.requesterDeviceId,
    reason: request.reason,
    ...(request.knownManifestRoot === undefined ? {} : { knownManifestRoot: request.knownManifestRoot }),
    requestedAt: request.requestedAt,
    expiresAt: request.expiresAt,
  })
}

export function restoreOfferSigningBytes(offer: Omit<RestoreOfferV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/restore-offer/v1',
    version: offer.version,
    requestId: offer.requestId,
    identityId: offer.identityId,
    requesterDeviceId: offer.requesterDeviceId,
    responderDeviceId: offer.responderDeviceId,
    manifestRoot: offer.manifestRoot,
    offeredAt: offer.offeredAt,
    expiresAt: offer.expiresAt,
  })
}

export function restoreCancelSigningBytes(cancel: Omit<RestoreCancelV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/restore-cancel/v1',
    version: cancel.version,
    requestId: cancel.requestId,
    identityId: cancel.identityId,
    requesterDeviceId: cancel.requesterDeviceId,
    cancelledAt: cancel.cancelledAt,
  })
}

export function restoreControlPullSigningBytes(pull: Omit<RestoreControlPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/restore-control-pull/v1',
    version: pull.version,
    identityId: pull.identityId,
    deviceId: pull.deviceId,
    kind: pull.kind,
    requestedAt: pull.requestedAt,
  })
}

export function mlsGroupCreationSigningBytes(value: Omit<MlsGroupCreationV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-group-creation/v1',
    version: value.version,
    groupId: value.groupId,
    identityId: value.identityId,
    creatorKid: value.creatorKid,
    roster: value.roster,
    createdAt: value.createdAt,
  })
}

export function mlsCommitSubmissionSigningBytes(value: Omit<MlsCommitSubmissionV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-commit-submission/v1',
    version: value.version,
    groupId: value.groupId,
    identityId: value.identityId,
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

export function mlsExternalCommitSubmissionSigningBytes(value: Omit<MlsExternalCommitSubmissionV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-external-commit-submission/v1',
    version: value.version,
    groupId: value.groupId,
    identityId: value.identityId,
    senderKid: value.senderKid,
    epoch: value.epoch,
    commit: bytesToBase64url(value.commit),
    ...(value.groupInfo === undefined ? {} : { groupInfo: bytesToBase64url(value.groupInfo) }),
    submittedAt: value.submittedAt,
  })
}

export function mlsGroupInfoPullSigningBytes(pull: Omit<MlsGroupInfoPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-group-info-pull/v1',
    version: pull.version,
    groupId: pull.groupId,
    identityId: pull.identityId,
    requesterKid: pull.requesterKid,
    requestedAt: pull.requestedAt,
  })
}

export function mlsKeyPackagePublishSigningBytes(value: Omit<MlsKeyPackagePublishV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-keypackage-publish/v1',
    version: value.version,
    identityId: value.identityId,
    kid: value.kid,
    packages: value.packages.map(bytesToBase64url),
    publishedAt: value.publishedAt,
  })
}

export function mlsKeyPackageTakeSigningBytes(value: Omit<MlsKeyPackageTakeV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-keypackage-take/v1',
    version: value.version,
    identityId: value.identityId,
    requesterKid: value.requesterKid,
    requestedAt: value.requestedAt,
  })
}

export function mlsSelfRemoveSubmissionSigningBytes(value: Omit<MlsSelfRemoveSubmissionV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-self-remove-submission/v1',
    version: value.version,
    groupId: value.groupId,
    identityId: value.identityId,
    senderKid: value.senderKid,
    epoch: value.epoch,
    proposal: bytesToBase64url(value.proposal),
    removedKid: value.removedKid,
    submittedAt: value.submittedAt,
  })
}

export function mlsPendingRemovalsClearSigningBytes(value: Omit<MlsPendingRemovalsClearV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-pending-removals-clear/v1',
    version: value.version,
    groupId: value.groupId,
    identityId: value.identityId,
    requesterKid: value.requesterKid,
    clearedKids: value.clearedKids,
    clearedAt: value.clearedAt,
  })
}

export function mlsDeliveriesPullSigningBytes(value: Omit<MlsDeliveriesPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-deliveries-pull/v1',
    version: value.version,
    groupId: value.groupId,
    identityId: value.identityId,
    requesterKid: value.requesterKid,
    afterSeq: value.afterSeq,
    requestedAt: value.requestedAt,
  })
}

export function mlsKeyPackageDropSigningBytes(value: Omit<MlsKeyPackageDropV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-keypackage-drop/v1',
    version: value.version,
    identityId: value.identityId,
    kid: value.kid,
    droppedAt: value.droppedAt,
  })
}

export function mlsKeyPackageCountPullSigningBytes(value: Omit<MlsKeyPackageCountPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-keypackage-count-pull/v1',
    version: value.version,
    identityId: value.identityId,
    kid: value.kid,
    requestedAt: value.requestedAt,
  })
}

export function mlsGroupsForPullSigningBytes(value: Omit<MlsGroupsForPullV1, 'signature'>): Uint8Array {
  return canonicalBytes({
    label: 'biset/mls-groups-for-pull/v1',
    version: value.version,
    identityId: value.identityId,
    requesterKid: value.requesterKid,
    requestedAt: value.requestedAt,
  })
}
