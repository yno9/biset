import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createMimiDeployment } from '../../src/mimi/deployment.ts'
import { deliveriesPullSigningBytes, submitMessageSigningBytes, updateRoomSigningBytes } from '../../src/mimi/authorizer.ts'
import { decodeDeliveriesWire, decodeSubmitMessageResponseWire, encodeDeliveriesPullRequestWire, encodeSubmitMessageRequestWire, encodeUpdateRoomRequestWire } from '../../src/mimi/wire.ts'
import { encodeMimiParticipantListUpdate, encodeMimiFrankingAgent, encodeMimiRoomMetadata } from '../../src/mimi/app-data.ts'
import { createMlsGroup, generateOwnKeyPackageForCredential, groupInfoForExternalJoin } from '../../src/mls/group.ts'
import { mlsSuite } from '../../src/vendor/mls/suite.ts'
import { createApplicationMessage, createCommit, encodeMlsMessage, type KeyPackage } from '../../src/vendor/mls/index.ts'
import { encodeCredential } from '../../src/vendor/mls/credential.ts'
import type { VisibleCredential } from '../../src/mimi/protocol-types.ts'

const at = '2026-09-01T00:00:00.000Z'
const roomId = 'mimi://hub.example/r/tree-authorized'

function credentialFromKeyPackage(user: string, client: string, kp: KeyPackage): VisibleCredential {
  return { kind: 'visible', user, client, credential: encodeCredential(kp.leafNode.credential), signaturePublicKey: kp.leafNode.signaturePublicKey }
}
interface Client { credential: VisibleCredential; secret: Uint8Array }
function client(user: string, fragment: string, marker: number): Client {
  const secret = ed25519.utils.randomSecretKey()
  return { secret, credential: { kind: 'visible', user, client: `${user}#${fragment}`, credential: new Uint8Array([marker]), signaturePublicKey: ed25519.getPublicKey(secret) } }
}
function signedUpdate(sender: Client, value: Parameters<typeof updateRoomSigningBytes>[0]) { return { ...value, signature: ed25519.sign(updateRoomSigningBytes(value), sender.secret) } }
function post(path: string, body: string): Request { return new Request(`https://mimi.test${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }) }

describe('MIMI tree-based credential authorization (PLAN §21: closes the memberCredentials sidecar gap)', () => {
  test('a member added by a real MLS commit, with NO memberCredentials sidecar entry, can still pull deliveries and submit -- via the tracked tree, not the sidecar', async () => {
    const alice = client('mimi://hub.example/u/alice', 'phone', 41)
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', publicBaseUrl: 'https://mimi.hub.example' })

    const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(alice.credential.client) })
    let group = await createMlsGroup(new TextEncoder().encode(roomId), own)
    const suite = await mlsSuite()
    const proposal = (componentId: number, update: Uint8Array) => ({ proposalType: 'app_data_update' as const, appDataUpdate: { componentId, operation: 'update' as const, update } })
    const aliceParticipant = { user: alice.credential.user, roleIndex: 1, clientIds: [alice.credential.client] }
    const metadata = { roomUri: roomId, roomName: 'tree-authorized' }

    const genesisCommit = await createCommit({ state: group, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [
        proposal(0x0021, encodeMimiFrankingAgent({ frankingSignatureKey: deployment.store.prepareFrankingKeys(roomId).signingPublicKey, credential: new TextEncoder().encode('https://mimi.hub.example') })),
        proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [aliceParticipant] })),
        proposal(0x0023, encodeMimiRoomMetadata(metadata)),
      ],
    })
    group = genesisCommit.newState
    // A real, verifiable GroupInfo -- this is what lets the hub start
    // tracking MLS public state at all (PLAN §21.4/§21.2).
    const genesisUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(genesisCommit.commit), groupInfo: await groupInfoForExternalJoin(group) },
      initialState: { basePolicy: new Uint8Array(), participantList: { participants: [aliceParticipant] }, memberCredentials: [alice.credential], metadata }, submittedAt: at,
    }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, genesisUnsigned))))).status).toBe(200)
    await new Promise(resolve => setTimeout(resolve, 20)) // trackMlsPublicState is fire-and-forget

    // Bob joins via a genuine `add` proposal -- but the /update request
    // deliberately carries NO `stateUpdate` at all, so `memberCredentials`
    // never gets a sidecar entry for him. Before this session's work, this
    // would leave Bob permanently unable to pull/submit in this room.
    const bobOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('mimi://hub.example/u/bob#laptop') })
    const bob = { credential: credentialFromKeyPackage('mimi://hub.example/u/bob', 'mimi://hub.example/u/bob#laptop', bobOwn.publicPackage) }
    const addCommit = await createCommit({ state: group, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [
        { proposalType: 'add', add: { keyPackage: bobOwn.publicPackage } },
        proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [{ user: bob.credential.user, roleIndex: 1 }] })),
      ],
    })
    const addUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '1',
      bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(addCommit.commit) },
      submittedAt: '2026-09-01T00:00:01.000Z',
    }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, addUnsigned))))).status).toBe(200)
    await new Promise(resolve => setTimeout(resolve, 20))

    // Confirm the sidecar genuinely never learned about Bob (this is what's
    // actually new here, not a workaround inside the test).
    expect(deployment.store.room(roomId)?.memberCredentials.some(c => c.kind === 'visible' && c.user === bob.credential.user)).toBe(false)
    expect(deployment.store.room(roomId)?.participantList.participants.some(p => p.user === bob.credential.user)).toBe(true)

    // Bob pulls deliveries -- authorized only via the tracked tree. The
    // tree-based check matches (credential, signaturePublicKey) as a pair
    // against a real leaf, so the request signs with the *same* signature
    // key the add proposal's KeyPackage carried (not a fresh one).
    const pullUnsigned = { version: 1 as const, protocol: 'mls10' as const, roomId, requester: bob.credential, afterSeq: 0, requestedAt: at }
    const pullSignature = ed25519.sign(deliveriesPullSigningBytes(pullUnsigned), bobOwn.privatePackage.signaturePrivateKey)
    const pullResponse = await deployment.fetch(post('/v1/mimi/deliveries/pull', encodeDeliveriesPullRequestWire({ ...pullUnsigned, signature: pullSignature })))
    expect(pullResponse.status).toBe(200)
    expect(decodeDeliveriesWire(await pullResponse.text()).length).toBeGreaterThan(0)

    // Bob submits a message -- also authorized only via the tracked tree.
    const submitUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: bob.credential, epoch: '2',
      appMessage: new Uint8Array([1, 2, 3]), frankAAD: { frankingTag: new Uint8Array(32).fill(3) }, frankingSignatureCiphersuite: 1, submittedAt: '2026-09-01T00:00:02.000Z',
    }
    const submitSignature = ed25519.sign(submitMessageSigningBytes(submitUnsigned), bobOwn.privatePackage.signaturePrivateKey)
    const submitResponse = await deployment.fetch(post(`/submitMessage/${encodeURIComponent(roomId)}`, encodeSubmitMessageRequestWire({ ...submitUnsigned, signature: submitSignature })))
    expect(submitResponse.status).toBe(200)
    expect(decodeSubmitMessageResponseWire(await submitResponse.text()).status).toBe('accepted')

    // A stranger with an unrelated key, claiming to be Bob, is still refused.
    const strangerSecret = ed25519.utils.randomSecretKey()
    const strangerCredential: VisibleCredential = { ...bob.credential, signaturePublicKey: ed25519.getPublicKey(strangerSecret) }
    const strangerUnsigned = { version: 1 as const, protocol: 'mls10' as const, roomId, requester: strangerCredential, afterSeq: 0, requestedAt: at }
    const strangerResponse = await deployment.fetch(post('/v1/mimi/deliveries/pull', encodeDeliveriesPullRequestWire({ ...strangerUnsigned, signature: ed25519.sign(deliveriesPullSigningBytes(strangerUnsigned), strangerSecret) })))
    expect(strangerResponse.status).toBe(403)

    deployment.close()
  })
})
