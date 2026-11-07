// What reaches this device from its mediator: Vault Sync from a sibling, a protocol message answered here (Discover Features,
// a Secure-Join step), or a message that becomes local Vault records (ingress-projector.ts).
import { answerTrustPing } from '../../didcomm/send-message.ts'
import { isBasicMessage } from '../../didcomm/basicmessage.ts'
import type { DidCommIngressProjector } from '../../didcomm/ingress-projector.ts'
import { isProjectableDidCommIngress } from '../../didcomm/ingress-projector.ts'
import type { RotationManager } from '../../didcomm/rotation-manager.ts'
import type { VaultSyncClient, VaultSyncMessage } from '../../didcomm/vault-sync.ts'
import { ingestTransportIngress } from '../../store/vault/ingress-ingest.ts'
import { rebuildLocalJmapProjection } from '../../store/vault/projection-rebuild.ts'
import { canonicalHash, sha256Bytes } from '../../../protocol/canonical.ts'
import type { DidCommPlaintext } from '../../../protocol/didcomm/message.ts'
import { isPing } from '../../../protocol/didcomm/trust-ping.ts'
import { VAULT_SYNC_STATE_REQUEST, VAULT_SYNC_STATE_RESPONSE, VAULT_SYNC_UPDATE } from '../../../protocol/didcomm/vault-sync-protocol.ts'
import { errorMessage } from '../../../protocol/error-message.ts'
import type { IngressEnvelopeV1 } from '../../../protocol/ingress.ts'
import type { AccountVault } from './account-vault.ts'
import { timed } from './boot-timing.ts'

export interface MediatorDelivery {
  plaintext: unknown
  senderKid: string
  ackId: string
  rawJwe: unknown
}

const VAULT_SYNC_TYPES: readonly unknown[] = [VAULT_SYNC_UPDATE, VAULT_SYNC_STATE_REQUEST, VAULT_SYNC_STATE_RESPONSE]

function mediatorIngressEnvelope(vault: AccountVault, mediatorUrl: string, recipientKid: string, delivery: MediatorDelivery): IngressEnvelopeV1 {
  const protectedPayload = new TextEncoder().encode(JSON.stringify(delivery.rawJwe))
  return {
    version: 1,
    ingressId: canonicalHash('biset/didcomm-wallet-mediator-ingress/v1', { mediatorUrl, recipientKid, queueId: delivery.ackId }),
    protocol: 'didcomm',
    recipientIdentityId: vault.identityId,
    recipientDeviceSnapshot: [vault.deviceId],
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    transportMetadata: {},
    sourceEvidence: new Uint8Array(0),
    protectedPayload,
    protectedPayloadHash: sha256Bytes(protectedPayload),
  }
}

/**
 * Besides Vault Sync, the only branch is the DidCommIngressProjector, which throws for every type it cannot project -- and a
 * throw here does NOT drop the message: watchMediatorLive leaves it unacknowledged on purpose, so the mediator re-delivers the
 * very same message on every reconnect, where it fails identically, forever. Retrying only ever helps a transient failure; an
 * unsupported type is permanent, so it is dropped deliberately (and visibly) instead. The Pickup ACK that follows the return is
 * the point: it is what keeps the queue moving for every message behind this one.
 */
export function incomingHandler(options: {
  vault: AccountVault
  vaultSync: VaultSyncClient
  projector: DidCommIngressProjector
  rotationManager: RotationManager
  /** A Secure-Join step is answered and never shown (secure-join.ts). */
  answerSecureJoin(message: DidCommPlaintext): Promise<boolean>
  /** A sibling may have added its device key to the DID document just before sending a sync message. */
  onSiblingSync(): Promise<void>
}): (delivery: MediatorDelivery, recipientKid: string, mediatorUrl: string) => Promise<void> {
  const { vault, vaultSync, rotationManager } = options
  const { identityId, store } = vault

  const receiveVaultSync = async (message: VaultSyncMessage, senderKid: string): Promise<void> => {
    await vaultSync.receive(message, senderKid)
    await options.onSiblingSync()
    // Merging the log and object store never by itself updates the separately stored projection the inbox renders from, so it
    // is rebuilt from every event this identity now has (a bare STATE_REQUEST adds nothing). The merge is the durable source of
    // truth and has already succeeded: a failure re-deriving the projection (one incompatible historical event breaks the whole
    // replay) must not count as this message having failed, which would leave it unacknowledged and redelivered forever,
    // wedging delivery to this device. The data is safe either way; only the inbox's rendering of it is at risk.
    if (message.type === VAULT_SYNC_STATE_REQUEST) return
    try {
      const projection = await rebuildLocalJmapProjection({ identityId, records: store, resolver: vault.boundary.resolver })
      await store.writeProjection(identityId, projection, { state: projection.state })
      await timed('refreshInbox', vault.refresh())
      // A sibling may have started a move: watch its inbox here too.
      await rotationManager.sync()
    } catch (error) {
      console.warn('[did.md Wallet Vault Sync projection rebuild]', errorMessage(error))
    }
  }

  return async (delivery, recipientKid, mediatorUrl) => {
    const candidate = delivery.plaintext as { type?: unknown }
    if (VAULT_SYNC_TYPES.includes(candidate.type)) return receiveVaultSync(delivery.plaintext as VaultSyncMessage, delivery.senderKid)
    const message = delivery.plaintext as DidCommPlaintext
    // Discover Features: answered here, never recorded (did-rotation.ts).
    if (await rotationManager.handleDiscoverFeatures(message, delivery.senderKid, recipientKid)) return
    if (isBasicMessage(message) && await options.answerSecureJoin(message)) return
    if (!isProjectableDidCommIngress(message)) {
      console.warn(`[did.md Wallet DIDComm] dropping unsupported message type ${message.type} from ${delivery.senderKid}`)
      return
    }
    // A direct delivery becomes local Vault records, which are mirrored to siblings as well: two watches for the same private
    // kid normally see the same live frame, but one sibling can ACK first or be reconnecting. Vault Sync is the durable
    // convergence path for that race.
    const before = new Set((await store.readVaultEvents(identityId)).map(event => event.id))
    const ingress = await ingestTransportIngress(mediatorIngressEnvelope(vault, mediatorUrl, recipientKid, delivery), options.projector, store)
    if (ingress.targetIds.length) await vault.projector.recomputeEmails(identityId, ingress.targetIds)
    else await vault.projector.rebuildAll(identityId)
    // Trust Ping 2.0: answer one that asked. Best-effort: the ping is already recorded, and a lost answer is exactly what a
    // ping exists to reveal to its sender.
    const receivingKey = rotationManager.ownKey(recipientKid)
    if (receivingKey) void answerTrustPing(message, { key: { fromKid: receivingKey.kid, x25519PrivateKey: receivingKey.x25519PrivateKey } })
      .then(result => { if (result && !result.ok) console.warn('[did.md Wallet Trust Ping response]', result.error) })
      .catch(error => console.warn('[did.md Wallet Trust Ping response]', errorMessage(error)))
    // What this message taught the contact cards (a counterparty's move, a confirmation) may start or end a watch; and a
    // counterparty that moved, or that writes, may be one this identity moves with too.
    await rotationManager.sync()
    if (isBasicMessage(message) || isPing(message)) {
      const publicDid = await rotationManager.counterpartyOf(delivery.senderKid)
      if (publicDid && !publicDid.startsWith('did:peer:')) {
        void (typeof message.from_prior === 'string' ? rotationManager.start(publicDid) : rotationManager.offer(publicDid))
          .catch(error => console.warn('[did.md Wallet DID Rotation]', errorMessage(error)))
      }
    }
    const added = (await store.readVaultEvents(identityId)).filter(event => !before.has(event.id))
    void vault.pushToSiblings(added).catch(error => console.warn('[did.md Wallet Vault Sync ingress push]', errorMessage(error)))
    await vault.refresh()
  }
}
