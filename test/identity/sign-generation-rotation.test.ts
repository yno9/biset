import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  addMembers,
  createMlsGroup,
  generateOwnKeyPackage,
  joinMlsGroup,
  memberKids,
  ownMlsDeviceCredential,
  processIncoming,
  rotateOwnCredentialAndRemoveMembers,
} from '../../src/client/mimi/group.ts'
import { createMlsDeviceCredential } from '../../src/client/mimi/device-credential.ts'

const generation1 = `1-${'a'.repeat(32)}`
const generation2 = `2-${'b'.repeat(32)}`

describe('Sign generation MLS transition', () => {
  test('updates the executing leaf and removes every sibling in one commit', async () => {
    const did = 'did:webvh:QmGeneration:alice.example'
    const root = ed25519.utils.randomSecretKey()
    const sign1 = root
    const sign2 = ed25519.utils.randomSecretKey()
    const leafA = ed25519.utils.randomSecretKey()
    const leafB = ed25519.utils.randomSecretKey()
    const credentialA = createMlsDeviceCredential(did, generation1, ed25519.getPublicKey(leafA), root, sign1)
    const credentialB = createMlsDeviceCredential(did, generation1, ed25519.getPublicKey(leafB), root, sign1)
    const ownA = await generateOwnKeyPackage(credentialA, leafA)
    const ownB = await generateOwnKeyPackage(credentialB, leafB)
    let stateA = await createMlsGroup(new TextEncoder().encode('generation-test'), ownA)
    const added = await addMembers(stateA, [ownB.publicPackage])
    stateA = added.state
    const stateB = await joinMlsGroup(added.welcome!, ownB, stateA.ratchetTree)

    const credentialA2 = createMlsDeviceCredential(did, generation2, credentialA.signaturePublicKey, root, sign2)
    const rotated = await rotateOwnCredentialAndRemoveMembers(stateA, credentialA2, [credentialB.deviceKid])

    expect(memberKids(rotated.state, did)).toEqual([credentialA.deviceKid])
    expect(ownMlsDeviceCredential(rotated.state).generation).toBe(generation2)
    const removedB = await processIncoming(stateB, rotated.commit)
    expect((removedB.state as unknown as { groupActiveState: { kind: string } }).groupActiveState.kind).toBe('removedFromGroup')
  })
})
