import { describe, expect, test } from 'bun:test'
import { createMlsGroup, generateOwnKeyPackageForCredential, groupInfoForExternalJoin } from '../../src/mls/group.ts'
import { mlsSuite } from '../../src/vendor/mls/suite.ts'
import { defaultAuthenticationService } from '../../src/vendor/mls/authenticationService.ts'
import { bootstrapPublicGroupStateFromGroupInfo, MimiGroupInfoBootstrapError } from '../../src/mimi/mls-group-info-bootstrap.ts'

describe('MIMI GroupInfo bootstrap (answers PLAN §21.4: how a hub learns a genesis confirmationTag)', () => {
  test('a real GroupInfo bootstraps a PublicGroupState matching the real ClientState it was produced from', async () => {
    const suite = await mlsSuite()
    const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('alice') })
    const alice = await createMlsGroup(new TextEncoder().encode('room'), own)
    const groupInfoBytes = await groupInfoForExternalJoin(alice)

    const tracked = await bootstrapPublicGroupStateFromGroupInfo(groupInfoBytes, defaultAuthenticationService, suite)

    expect(tracked.ratchetTree).toEqual(alice.ratchetTree)
    expect(tracked.groupContext).toEqual(alice.groupContext)
    expect(tracked.confirmationTag).toEqual(alice.confirmationTag)
  })

  test('rejects a GroupInfo whose signature has been tampered with', async () => {
    const suite = await mlsSuite()
    const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('alice') })
    const alice = await createMlsGroup(new TextEncoder().encode('room'), own)
    const groupInfoBytes = await groupInfoForExternalJoin(alice)
    const tampered = groupInfoBytes.slice()
    tampered[tampered.length - 1] = (tampered[tampered.length - 1]! + 1) % 256

    await expect(bootstrapPublicGroupStateFromGroupInfo(tampered, defaultAuthenticationService, suite)).rejects.toThrow(MimiGroupInfoBootstrapError)
  })
})
