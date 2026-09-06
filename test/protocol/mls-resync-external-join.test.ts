// Regression for `joinGroupExternal`'s (protocol/mls/createCommit.ts)
// `resync` bug found 2026-09-06: upstream computed the leaf index to remove
// unconditionally from `resync`, with no check for "no such leaf"
// (Array.prototype.findIndex returning -1). `toNodeIndex` brand-casts
// without validating range, so a resync request with no actual match
// silently produced `nodeToLeafIndex(-1)` === -0.5 -- a corrupt Remove
// proposal, never exercised because resync's only prior caller (a
// did:webvh domain move, removed with native login) always had a
// guaranteed match.
//
// The new caller this fix is for (vault-room.ts's joinMimiVaultRoom,
// retrying with resync: true after a device's own local MLS state was lost
// and the hub rejects its plain rejoin as a duplicate participant) cannot
// guarantee a match up front, so "no match" has to be a safe no-op.
import { describe, expect, test } from 'bun:test'
import {
  createMlsGroup, generateOwnKeyPackage, groupInfoForExternalJoin, joinGroupExternally, memberList, processIncoming,
} from '../../src/client/mls/group.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'

const identityId = 'did:web:alice.example'
const groupId = new TextEncoder().encode('resync-test-group')

describe('joinGroupExternal resync', () => {
  test('resync: true safely no-ops when no leaf matches the joiner (the bug)', async () => {
    const deviceA = await mlsDeviceFixture(identityId)
    const stateA = await createMlsGroup(groupId, deviceA.own)
    const deviceC = await mlsDeviceFixture(identityId) // never in the group

    const groupInfo = await groupInfoForExternalJoin(stateA)
    // Pre-fix, this line either threw deep inside the vendored tree-math
    // helpers on a fractional/negative leaf index, or produced a state that
    // does not actually contain the joiner -- neither of which resync:
    // true is supposed to cause when nothing matches.
    const joined = await joinGroupExternally(groupInfo, deviceC.own, undefined, true)

    const members = memberList(joined.state)
    expect(members).toHaveLength(2) // A, and the newly joined C -- nobody removed
    expect(members.some(member => member.kid === deviceA.kid)).toBe(true)
    expect(members.some(member => member.kid === deviceC.kid)).toBe(true)
  })

  test('resync: true removes the joiner\'s own stale leaf and adds the fresh one', async () => {
    const deviceA = await mlsDeviceFixture(identityId)
    const stateA0 = await createMlsGroup(groupId, deviceA.own)
    const deviceB = await mlsDeviceFixture(identityId, deviceA.rootPrivateKey)

    // Device B's first join -- the leaf that gets "lost locally" in the
    // real scenario: the hub durably has it, but the device itself has no
    // local record of ever joining.
    const firstJoin = await joinGroupExternally(await groupInfoForExternalJoin(stateA0), deviceB.own)
    expect(memberList(firstJoin.state)).toHaveLength(2)

    // A processes B's join commit, so the GroupInfo B's resync attempt
    // fetches below comes from a state that actually contains B's stale
    // leaf -- matching what the real hub would serve.
    const stateA1 = (await processIncoming(stateA0, firstJoin.commit)).state

    // Device B rejoins with a FRESH KeyPackage generated from the SAME
    // credential and signature key as before -- exactly what
    // generateOwnKeyPackage(options.credential, options.signaturePrivateKey)
    // produces on a plain retry in vault-room.ts's joinMimiVaultRoom. Not a
    // second device: the same signature key is what makes this leaf
    // recognizable as B's own stale one to `compareKeyPackageToLeafNode`.
    const retryOwn = await generateOwnKeyPackage(deviceB.credential, deviceB.signaturePrivateKey)
    const resynced = await joinGroupExternally(await groupInfoForExternalJoin(stateA1), retryOwn, undefined, true)

    const members = memberList(resynced.state)
    expect(members).toHaveLength(2) // A, and B's one current leaf -- no duplicate
    expect(members.filter(member => member.kid === deviceB.kid)).toHaveLength(1)
  })
})
