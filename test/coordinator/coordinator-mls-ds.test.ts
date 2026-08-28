import { afterEach, describe, expect, test } from 'bun:test'
import { Database } from 'bun:sqlite'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createVaultCoordinatorFetchHandler } from '../../src/coordinator/app.ts'
import type { VaultAccessPrincipal, VaultAccessTokenVerifier } from '../../src/coordinator/auth.ts'
import { SqliteVaultCoordinatorStore } from '../../src/coordinator/store.ts'
import { vaultGroupViewHash } from '../../src/protocol/vault-group-view.ts'
import { vaultMlsKeyPackageSigningBytes, vaultMlsMemberRequestSigningBytes, vaultMlsTransitionSigningBytes } from '../../src/protocol/vault-mls-ds.ts'
import { createVaultMlsGenesis, createVaultMlsJoinCandidate, joinVaultMlsFromWelcome, prepareVaultMlsAdd } from '../../src/mls/vault-group.ts'
import { VaultCoordinatorTransport } from '../../src/vault/coordinator-transport.ts'

const databases: Database[] = []
afterEach(() => { for (const database of databases.splice(0)) database.close() })

describe('Coordinator Vault MLS Delivery Service', () => {
  test('carries an opaque KeyPackage, atomic Add transition, and Welcome between two devices', async () => {
    const database = new Database(':memory:')
    databases.push(database)
    const store = new SqliteVaultCoordinatorStore(database)
    const verifier: VaultAccessTokenVerifier = { async verify(): Promise<VaultAccessPrincipal> { return { subject: 'owner', scopes: new Set(['vault.create', 'vault.group.install']), expiresAt: Number.MAX_SAFE_INTEGER } } }
    const handler = createVaultCoordinatorFetchHandler({ store, accessTokens: verifier })
    const transport = new VaultCoordinatorTransport({
      baseUrl: 'https://coordinator.example',
      accessTokens: { async getAccessToken() { return 'owner-token' } },
      fetch: ((input: RequestInfo | URL, init?: RequestInit) => handler(new Request(input, init))) as typeof fetch,
    })

    const first = await createVaultMlsGenesis()
    expect(await transport.createVault(first.groupView)).toBe(vaultGroupViewHash(first.groupView))
    const inviteRequest = { version: 1 as const, vaultId: first.vaultId, memberId: first.memberId, afterEpoch: '1', requestedAt: '2026-08-28T07:59:58.000Z' }
    const invitation = await transport.createMlsInvitation({ ...inviteRequest, signature: ed25519.sign(vaultMlsMemberRequestSigningBytes(inviteRequest), first.memberSignaturePrivateKey) })
    expect(invitation.invitation).toMatch(/^vin_[A-Za-z0-9_-]{43}$/)
    expect(await transport.redeemMlsInvitation({ version: 1, invitation: invitation.invitation, redeemedAt: '2026-08-28T07:59:59.000Z' })).toEqual({ vaultId: first.vaultId })
    await expect(transport.redeemMlsInvitation({ version: 1, invitation: invitation.invitation, redeemedAt: '2026-08-28T07:59:59.000Z' })).rejects.toThrow('404')
    const second = await createVaultMlsJoinCandidate()
    const keyPackageUnsigned = {
      version: 1 as const,
      vaultId: first.vaultId,
      memberId: second.memberId,
      signaturePublicKey: ed25519.getPublicKey(second.memberSignaturePrivateKey),
      keyPackage: second.encodedKeyPackage,
      publishedAt: '2026-08-28T08:00:00.000Z',
    }
    await transport.publishMlsKeyPackage({ ...keyPackageUnsigned, signature: ed25519.sign(vaultMlsKeyPackageSigningBytes(keyPackageUnsigned), second.memberSignaturePrivateKey) })

    const claimUnsigned = { version: 1 as const, vaultId: first.vaultId, memberId: first.memberId, afterEpoch: '1', requestedAt: '2026-08-28T08:00:01.000Z' }
    const packages = await transport.pullMlsKeyPackages({ ...claimUnsigned, signature: ed25519.sign(vaultMlsMemberRequestSigningBytes(claimUnsigned), first.memberSignaturePrivateKey) })
    expect(packages).toHaveLength(1)
    const pending = await prepareVaultMlsAdd({ encodedState: first.encodedState, groupView: first.groupView, localMemberId: first.memberId, memberSignaturePrivateKey: first.memberSignaturePrivateKey }, packages[0]!.keyPackage, '1')
    const transitionUnsigned = { version: 1 as const, groupView: pending.groupView, commit: pending.commit, welcomes: [{ memberId: second.memberId, payload: pending.welcome }], submittedAt: '2026-08-28T08:00:02.000Z' }
    const transition = { ...transitionUnsigned, signature: ed25519.sign(vaultMlsTransitionSigningBytes(transitionUnsigned), first.memberSignaturePrivateKey) }
    expect(await transport.installMlsTransition(transition)).toBe(vaultGroupViewHash(pending.groupView))
    expect(await transport.installMlsTransition(transition)).toBe(vaultGroupViewHash(pending.groupView))

    const welcomeUnsigned = { version: 1 as const, vaultId: first.vaultId, memberId: second.memberId, afterEpoch: '0', requestedAt: '2026-08-28T08:00:03.000Z' }
    const delivered = await transport.pullMlsWelcome({ ...welcomeUnsigned, signature: ed25519.sign(vaultMlsMemberRequestSigningBytes(welcomeUnsigned), second.memberSignaturePrivateKey) })
    expect(delivered?.groupView.groupEpoch).toBe('2')
    const joined = await joinVaultMlsFromWelcome(second, delivered!.welcome, delivered!.groupView)
    expect(joined.encodedState.length).toBeGreaterThan(0)

    const transitions = await transport.pullMlsTransitions({ ...claimUnsigned, signature: ed25519.sign(vaultMlsMemberRequestSigningBytes(claimUnsigned), first.memberSignaturePrivateKey) })
    expect(transitions.map(item => item.groupView.groupEpoch)).toEqual(['2'])
    expect(await transport.pullMlsKeyPackages({ ...claimUnsigned, signature: ed25519.sign(vaultMlsMemberRequestSigningBytes(claimUnsigned), first.memberSignaturePrivateKey) })).toEqual([])
    pending.confirm()
  })

  test('rejects a KeyPackage not signed by the joining member key', async () => {
    const database = new Database(':memory:')
    databases.push(database)
    const store = new SqliteVaultCoordinatorStore(database)
    const genesis = await createVaultMlsGenesis()
    store.create(genesis.groupView, 'owner')
    const candidate = await createVaultMlsJoinCandidate()
    const unsigned = { version: 1 as const, vaultId: genesis.vaultId, memberId: candidate.memberId, signaturePublicKey: ed25519.getPublicKey(candidate.memberSignaturePrivateKey), keyPackage: candidate.encodedKeyPackage, publishedAt: '2026-08-28T08:10:00.000Z' }
    expect(() => store.publishKeyPackage({ ...unsigned, signature: ed25519.sign(vaultMlsKeyPackageSigningBytes(unsigned), new Uint8Array(32).fill(9)) }, 'owner')).toThrow('publisher signature')

    const request = { version: 1 as const, vaultId: genesis.vaultId, memberId: genesis.memberId, afterEpoch: '1', requestedAt: '2026-08-28T08:10:01.000Z' }
    const signed = { ...request, signature: ed25519.sign(vaultMlsMemberRequestSigningBytes(request), genesis.memberSignaturePrivateKey) }
    const now = new Date('2026-08-28T08:10:01.000Z')
    const invitation = store.createMlsInvitation(signed, 'owner', now)
    expect(() => store.redeemMlsInvitation({ version: 1, invitation: invitation.invitation, redeemedAt: now.toISOString() }, 'another-owner', now)).toThrow('not found')
    expect(store.redeemMlsInvitation({ version: 1, invitation: invitation.invitation, redeemedAt: now.toISOString() }, 'owner', now)).toEqual({ vaultId: genesis.vaultId })
  })
})
