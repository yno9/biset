import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { vaultGroupViewSigningBytes } from '../../src/protocol/vault-group-view.ts'
import { decodeStateWithAuthenticationService, encryptApplication, processIncoming } from '../../src/mls/group.ts'
import { createVaultMlsGenesis, createVaultMlsJoinCandidate, joinVaultMlsFromWelcome, prepareVaultMlsAdd, vaultAuthenticationService, vaultMlsGroupId } from '../../src/mls/vault-group.ts'

describe('Vault-specific MLS genesis', () => {
  test('uses only random Vault identifiers and binds the signed view to a real MLS state', async () => {
    const genesis = await createVaultMlsGenesis()
    const state = decodeStateWithAuthenticationService(genesis.encodedState, vaultAuthenticationService)
    expect(genesis.vaultId).toMatch(/^vlt_[A-Za-z0-9_-]{43}$/)
    expect(genesis.memberId).toMatch(/^vmb_[A-Za-z0-9_-]{43}$/)
    expect(equalBytes(state.groupContext.groupId, vaultMlsGroupId(genesis.vaultId))).toBeTrue()
    expect(state.groupContext.epoch).toBe(1n)
    expect(state.groupContext.confirmedTranscriptHash).toHaveLength(32)
    expect(genesis.groupView).toMatchObject({ groupEpoch: '1', previousViewHash: null, installerMemberId: genesis.memberId })
    expect(ed25519.verify(genesis.groupView.signature, vaultGroupViewSigningBytes(genesis.groupView), genesis.groupView.members[0]!.signaturePublicKey)).toBeTrue()
    expect(JSON.stringify(genesis.groupView)).not.toContain('did:')
  })

  test('adds an opaque second device by KeyPackage and Welcome with matching MLS state', async () => {
    const first = await createVaultMlsGenesis()
    const second = await createVaultMlsJoinCandidate()
    const pending = await prepareVaultMlsAdd({
      encodedState: first.encodedState,
      groupView: first.groupView,
      localMemberId: first.memberId,
      memberSignaturePrivateKey: first.memberSignaturePrivateKey,
    }, second.encodedKeyPackage, '1')

    expect(pending.memberId).toBe(second.memberId)
    expect(pending.groupView.groupEpoch).toBe('2')
    expect(pending.groupView.members.map(member => member.memberId)).toEqual([first.memberId, second.memberId])
    expect(JSON.stringify(pending.groupView)).not.toContain('did:')

    const joined = await joinVaultMlsFromWelcome(second, pending.welcome, pending.groupView)
    const firstState = decodeStateWithAuthenticationService(pending.encodedState, vaultAuthenticationService)
    const secondState = decodeStateWithAuthenticationService(joined.encodedState, vaultAuthenticationService)
    const plaintext = new TextEncoder().encode('second-device-ready')
    const encrypted = await encryptApplication(firstState, plaintext)
    const received = await processIncoming(secondState, encrypted.wire)
    expect(received.kind).toBe('message')
    if (received.kind !== 'message') throw new Error('expected MLS application message')
    expect(new TextDecoder().decode(received.message)).toBe('second-device-ready')
    pending.confirm()
    pending.confirm()
  })
})
