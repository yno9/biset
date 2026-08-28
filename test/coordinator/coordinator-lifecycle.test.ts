import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { vaultGroupViewHash, vaultGroupViewSigningBytes, type VaultGroupViewV1 } from '../../src/protocol/vault-group-view.ts'
import { advanceVaultCoordinatorGroup, createAndProvisionVaultCoordinator, provisionVaultCoordinator } from '../../src/vault/coordinator-lifecycle.ts'
import type { LocalVaultCoordinatorBindingV1 } from '../../src/vault/store.ts'

const identityId = 'did:webvh:lifecycle:anchor.example'
const vaultId = `vlt_${'G'.repeat(43)}` as const
const secret = new Uint8Array(32).fill(31)

describe('local Vault Coordinator lifecycle', () => {
  test('persists create only after the remote accepted the exact genesis view', async () => {
    let local: LocalVaultCoordinatorBindingV1 | undefined
    const binding = createBinding(view('1', null))
    await provisionVaultCoordinator(memoryStore(() => local, value => { local = value }), { async createVault(value) { return vaultGroupViewHash(value) } }, binding)
    expect(local).toMatchObject({ identityId, groupView: { vaultId, groupEpoch: '1' } })
  })

  test('creates an identity-free Vault MLS genesis before activating its local binding', async () => {
    let local: LocalVaultCoordinatorBindingV1 | undefined
    const created = await createAndProvisionVaultCoordinator(
      memoryStore(() => local, value => { local = value }),
      { async createVault(value) { expect(JSON.stringify(value)).not.toContain('did:'); return vaultGroupViewHash(value) } },
      identityId,
      'https://coordinator.biset.md',
      () => new Date('2026-08-28T05:00:00.000Z'),
    )
    expect(created.identityId).toBe(identityId)
    expect(created.groupView.vaultId).toMatch(/^vlt_/)
    expect(created.localMemberId).toMatch(/^vmb_/)
    expect(created.vaultMlsState.length).toBeGreaterThan(0)
    expect(local?.groupView.vaultId).toBe(created.groupView.vaultId)
  })

  test('does not activate a local binding when the remote returns another head', async () => {
    let local: LocalVaultCoordinatorBindingV1 | undefined
    const binding = createBinding(view('1', null))
    await expect(provisionVaultCoordinator(memoryStore(() => local, value => { local = value }), { async createVault() { return `sha256:${'X'.repeat(43)}` } }, binding)).rejects.toThrow('does not match')
    expect(local).toBeUndefined()
  })

  test('advances the remote head before atomically replacing the local accepted view', async () => {
    const genesis = view('1', null)
    let local: LocalVaultCoordinatorBindingV1 | undefined = createBinding(genesis)
    const nextView = view('2', vaultGroupViewHash(genesis))
    const transition = { version: 1 as const, groupView: nextView, commit: new Uint8Array([1]), welcomes: [], submittedAt: '2026-08-28T04:00:30.000Z', signature: new Uint8Array(64) }
    const updated = await advanceVaultCoordinatorGroup(memoryStore(() => local, value => { local = value }), {
      async installMlsTransition(value) {
        expect(local?.groupView.groupEpoch).toBe('1')
        return vaultGroupViewHash(value.groupView)
      },
    }, identityId, { groupView: nextView, transition, vaultMlsState: new Uint8Array([2]), localMemberId: 'member-a', memberSignaturePrivateKey: secret, updatedAt: '2026-08-28T04:01:00.000Z' })
    expect(updated.groupView.groupEpoch).toBe('2')
    expect(local?.groupView.groupEpoch).toBe('2')
  })
})

function memoryStore(read: () => LocalVaultCoordinatorBindingV1 | undefined, write: (value: LocalVaultCoordinatorBindingV1 | undefined) => void) {
  return {
    async readCoordinatorBinding() { return read() },
    async writeCoordinatorBinding(value: LocalVaultCoordinatorBindingV1) { write(value) },
    async clearCoordinatorBinding() { write(undefined) },
  }
}

function view(epoch: string, previousViewHash: string | null): VaultGroupViewV1 {
  const unsigned = {
    version: 1 as const,
    vaultId,
    groupId: new Uint8Array(32).fill(12),
    groupEpoch: epoch,
    confirmedTranscriptHash: new Uint8Array(32).fill(Number(epoch) + 40),
    previousViewHash,
    members: [{ memberId: 'member-a', signaturePublicKey: ed25519.getPublicKey(secret), deliveryFloor: '1' }],
    installerMemberId: 'member-a',
  }
  return { ...unsigned, signature: ed25519.sign(vaultGroupViewSigningBytes(unsigned), secret) }
}

function createBinding(groupView: VaultGroupViewV1): LocalVaultCoordinatorBindingV1 {
  return { version: 1, identityId, coordinatorUrl: 'https://coordinator.biset.md', groupView, vaultMlsState: new Uint8Array([1]), localMemberId: 'member-a', memberSignaturePrivateKey: secret, createdAt: '2026-08-28T04:00:00.000Z', updatedAt: '2026-08-28T04:00:00.000Z' }
}
