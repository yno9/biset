import { vaultGroupViewHash, type VaultGroupViewV1 } from '../protocol/vault-group-view.ts'
import type { IdentityId } from '../protocol/ids.ts'
import type { LocalVaultCoordinatorBindingStore, LocalVaultCoordinatorBindingV1 } from './store.ts'
import { createVaultMlsGenesis } from '../mls/vault-group.ts'
import type { VaultMlsTransitionV1 } from '../protocol/vault-mls-ds.ts'

export interface VaultCoordinatorGroupTransport {
  createVault(view: VaultGroupViewV1): Promise<string>
  installMlsTransition(value: VaultMlsTransitionV1): Promise<string>
}

/** Creates a brand-new opaque Vault MLS group and activates it only after the
 * Coordinator has accepted the exact signed genesis view. */
export async function createAndProvisionVaultCoordinator(
  store: LocalVaultCoordinatorBindingStore,
  transport: Pick<VaultCoordinatorGroupTransport, 'createVault'>,
  identityId: IdentityId,
  coordinatorUrl: string,
  now: () => Date = () => new Date(),
): Promise<LocalVaultCoordinatorBindingV1> {
  if (await store.readCoordinatorBinding(identityId)) throw new Error('this local Vault already has a Coordinator binding')
  const url = new URL(coordinatorUrl)
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new TypeError('Coordinator URL must be an HTTPS origin or base path')
  const genesis = await createVaultMlsGenesis()
  const createdAt = now().toISOString()
  return provisionVaultCoordinator(store, transport, {
    version: 1,
    identityId,
    coordinatorUrl: url.href.replace(/\/$/, ''),
    groupView: genesis.groupView,
    vaultMlsState: genesis.encodedState,
    localMemberId: genesis.memberId,
    memberSignaturePrivateKey: genesis.memberSignaturePrivateKey,
    createdAt,
    updatedAt: createdAt,
  })
}

/**
 * Creates the remote opaque partition before making it active locally. A lost
 * response is safe because both remote create and the local put are idempotent.
 */
export async function provisionVaultCoordinator(
  store: LocalVaultCoordinatorBindingStore,
  transport: Pick<VaultCoordinatorGroupTransport, 'createVault'>,
  binding: LocalVaultCoordinatorBindingV1,
): Promise<LocalVaultCoordinatorBindingV1> {
  if (await store.readCoordinatorBinding(binding.identityId)) throw new Error('this local Vault already has a Coordinator binding')
  const remoteHash = await transport.createVault(binding.groupView)
  assertAcceptedHash(remoteHash, binding.groupView)
  await store.writeCoordinatorBinding(binding)
  return binding
}

/**
 * Installs a signed next view remotely first, then advances the local accepted
 * head. If the local write fails, retrying the same view converges safely.
 */
export async function advanceVaultCoordinatorGroup(
  store: LocalVaultCoordinatorBindingStore,
  transport: Pick<VaultCoordinatorGroupTransport, 'installMlsTransition'>,
  identityId: IdentityId,
  next: Pick<LocalVaultCoordinatorBindingV1, 'groupView' | 'vaultMlsState' | 'localMemberId' | 'memberSignaturePrivateKey' | 'updatedAt'> & { transition: VaultMlsTransitionV1 },
): Promise<LocalVaultCoordinatorBindingV1> {
  const current = await store.readCoordinatorBinding(identityId)
  if (!current) throw new Error('this local Vault has no Coordinator binding')
  if (next.groupView.vaultId !== current.groupView.vaultId) throw new TypeError('Coordinator group update cannot change vaultId')
  if (next.groupView.previousViewHash !== vaultGroupViewHash(current.groupView)) throw new TypeError('Coordinator group update does not extend the local accepted view')
  if (vaultGroupViewHash(next.transition.groupView) !== vaultGroupViewHash(next.groupView)) throw new TypeError('Coordinator MLS transition does not carry the next group view')
  const remoteHash = await transport.installMlsTransition(next.transition)
  assertAcceptedHash(remoteHash, next.groupView)
  const updated: LocalVaultCoordinatorBindingV1 = {
    ...current,
    groupView: next.groupView,
    vaultMlsState: next.vaultMlsState,
    localMemberId: next.localMemberId,
    memberSignaturePrivateKey: next.memberSignaturePrivateKey,
    updatedAt: next.updatedAt,
  }
  await store.writeCoordinatorBinding(updated)
  return updated
}

function assertAcceptedHash(remoteHash: string, view: VaultGroupViewV1): void {
  if (remoteHash !== vaultGroupViewHash(view)) throw new Error('Coordinator accepted group-view hash does not match the submitted view')
}
