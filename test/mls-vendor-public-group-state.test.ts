import { describe, expect, test } from 'bun:test'
import { createMlsGroup, generateOwnKeyPackageForCredential } from '../src/mls/group.ts'
import { mlsSuite } from '../src/vendor/mls/suite.ts'
import { createCommit, type PublicMessage } from '../src/vendor/mls/index.ts'
import { defaultAuthenticationService } from '../src/vendor/mls/authenticationService.ts'
import { applyPublicCommit, initialPublicGroupState, verifyPublicMessageSignature } from '../src/vendor/mls/publicGroupState.ts'

/**
 * Cross-checks the new public (no-private-key) group state tracker against
 * the vendor library's own real, member-side commit application: the
 * tracker, given only what a hub actually has (a genesis ratchet_tree/
 * GroupContext, then each subsequent commit's PublicMessage bytes), must
 * arrive at the exact same ratchetTree/groupContext a real member computes
 * -- proving `applyPublicCommit` isn't just structurally plausible but
 * numerically identical to the trusted implementation for real commits.
 */
describe('MLS vendor public group state (server-side tree tracking without private keys)', () => {
  test('tracks a genuine two-member commit identically to the real client-side ClientState', async () => {
    const suite = await mlsSuite()
    const aliceOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('alice') })
    const bobOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('bob') })
    const alice = await createMlsGroup(new TextEncoder().encode('room'), aliceOwn)

    // What a hub genuinely has at genesis: the tree/GroupContext, and
    // (see the test's own note below) the genesis confirmationTag -- a
    // real value the group's creation computes, not derivable from public
    // data alone, so a real hub wire-up would need this conveyed somehow
    // (PLAN_biset-mimi-server.md §21 flags this as an open wire-format
    // question, not solved by this test).
    let tracked = await initialPublicGroupState(alice.ratchetTree, alice.groupContext, defaultAuthenticationService, suite)
    tracked = { ...tracked, confirmationTag: alice.confirmationTag }

    const addCommit = await createCommit({ state: alice, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [{ proposalType: 'add', add: { keyPackage: bobOwn.publicPackage } }],
    })
    if (addCommit.commit.wireformat !== 'mls_public_message') throw new Error('expected a PublicMessage commit')
    const publicMessage: PublicMessage = addCommit.commit.publicMessage

    expect(await verifyPublicMessageSignature(tracked, publicMessage, 'mls_public_message', suite)).toBe(true)

    tracked = await applyPublicCommit(tracked, publicMessage, defaultAuthenticationService, suite)

    expect(tracked.ratchetTree).toEqual(addCommit.newState.ratchetTree)
    expect(tracked.groupContext).toEqual(addCommit.newState.groupContext)
    expect(tracked.confirmationTag).toEqual(addCommit.newState.confirmationTag)
  })

  test('rejects a commit whose signature does not match the tracked tree', async () => {
    const suite = await mlsSuite()
    const aliceOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('alice') })
    const bobOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('bob') })
    const alice = await createMlsGroup(new TextEncoder().encode('room'), aliceOwn)
    let tracked = await initialPublicGroupState(alice.ratchetTree, alice.groupContext, defaultAuthenticationService, suite)
    tracked = { ...tracked, confirmationTag: alice.confirmationTag }

    const addCommit = await createCommit({ state: alice, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [{ proposalType: 'add', add: { keyPackage: bobOwn.publicPackage } }],
    })
    if (addCommit.commit.wireformat !== 'mls_public_message') throw new Error('expected a PublicMessage commit')
    const publicMessage: PublicMessage = addCommit.commit.publicMessage
    const tampered: PublicMessage = { ...publicMessage, auth: { ...publicMessage.auth, signature: new Uint8Array(publicMessage.auth.signature.length).fill(7) } }

    expect(await verifyPublicMessageSignature(tracked, tampered, 'mls_public_message', suite)).toBe(false)
    await expect(applyPublicCommit(tracked, tampered, defaultAuthenticationService, suite)).rejects.toThrow()
  })
})
