import type { DeviceId, IdentityId } from '../protocol/ids.ts'
import type { IngressAckSigner, IngressCommitter, IngressVerifierProjector } from '../vault/ingress-ingest.ts'
import { ingestIngress } from '../vault/ingress-ingest.ts'
import type { IngressPullSigner, IngressPullTransport } from '../vault/ingress-sync.ts'
import { synchronizeIngress, type IngressSyncResult } from '../vault/ingress-sync.ts'
import type { VaultDeliveryAppendSigner, VaultDeliveryAppendTransport, VaultDeliveryOutboxFlushResult } from '../vault/delivery-outbox.ts'
import { flushVaultDeliveryOutbox } from '../vault/delivery-outbox.ts'
import type { IngressAckOutboxReader, VaultDeliveryOutboxReader } from '../vault/store.ts'

export interface MailIngressWorkflowOptions {
  identityId: IdentityId
  deviceId: DeviceId
  store: IngressAckOutboxReader & VaultDeliveryOutboxReader
  ingressTransport: IngressPullTransport
  deliveryTransport: VaultDeliveryAppendTransport
  /** Optional cutover hook for a Vault Coordinator binding. */
  flushDelivery?: () => Promise<VaultDeliveryOutboxFlushResult>
  signer: IngressAckSigner & IngressPullSigner & VaultDeliveryAppendSigner
  projector: IngressVerifierProjector
  committer: IngressCommitter
  limit?: number
  now?: () => Date
}

export interface MailIngressWorkflowResult {
  ingress: IngressSyncResult
  deliveryBefore: VaultDeliveryOutboxFlushResult
  deliveryAfter: VaultDeliveryOutboxFlushResult
}

/**
 * Concrete endpoint order for externally delivered mail. It does not give the
 * core a mailbox API: it only turns a claimed opaque ingress into a local
 * vault commit, acknowledges that commit, then appends the resulting shared
 * vault pack for sibling devices.
 */
export async function synchronizeMailIngress(options: MailIngressWorkflowOptions): Promise<MailIngressWorkflowResult> {
  if (!options.identityId || !options.deviceId || options.signer.deviceId !== options.deviceId) {
    throw new TypeError('mail ingress workflow identity or signer is invalid')
  }
  const limit = options.limit ?? 32
  const now = options.now ?? (() => new Date())
  const flushDelivery = options.flushDelivery ?? (() => flushVaultDeliveryOutbox(options.store, options.deliveryTransport, options.signer, options.identityId, limit, now))
  const deliveryBefore = await flushDelivery()
  const ingress = await synchronizeIngress(options.store, options.ingressTransport, {
    ingest: envelope => ingestIngress(envelope, options.signer, options.projector, options.committer, now),
  }, options.signer, options.identityId, options.deviceId, limit, now)
  const deliveryAfter = await flushDelivery()
  return { ingress, deliveryBefore, deliveryAfter }
}
