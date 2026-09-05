import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createMimiDeployment } from '../../src/server/mimi/deployment.ts'
import { decryptIdentityLink, encryptIdentityLink } from '../../src/server/mimi/anon/identity-link.ts'
import {
  deliveriesPullSigningBytes,
  deliveriesWatchSigningBytes,
  authorizeKeyPackagePublish,
  groupInfoRequestSigningBytes,
  groupInfoResponseSigningBytes,
  keyPackagePublishSigningBytes,
  keyMaterialSigningBytes,
  submitMessageSigningBytes,
  updateRoomSigningBytes,
} from '../../src/shared/mimi/authorizer.ts'
import {
  decodeDeliveriesWire,
  decodeGroupInfoResponseWire,
  decodeGroupInfoRatchetTreeBundle,
  decodeKeyMaterialResponseWire,
  decodeKeyPackagePublishResponseWire,
  decodeUpdateRoomResponseWire,
  encodeDeliveriesPullRequestWire,
  encodeDeliveriesWatchRequestWire,
  encodeGroupInfoRequestWire,
  encodeKeyMaterialRequestWire,
  encodeKeyPackagePublishWire,
  decodeFrankWire,
  decodeFrankingAgentDataWire,
  encodeSubmitMessageRequestWire,
  encodeUpdateRoomRequestWire,
} from '../../src/shared/mimi/wire.ts'
import type { PseudonymousCredential, VisibleCredential } from '../../src/shared/mimi/protocol-types.ts'
import { createCommit, encodeMlsMessage, type KeyPackage } from '../../src/vendor/mls/index.ts'
import { encodeCredential } from '../../src/vendor/mls/credential.ts'
import { decryptWithLabel } from '../../src/vendor/mls/crypto/hpke.ts'
import { encodeWelcome } from '../../src/vendor/mls/welcome.ts'
import { encodeMimiFrankingAgent, encodeMimiParticipantListUpdate, encodeMimiRoomMetadata } from '../../src/shared/mimi/app-data.ts'
import { createMlsGroup, generateOwnKeyPackageForCredential } from '../../src/mls/group.ts'
import { mlsSuite } from '../../src/vendor/mls/suite.ts'

interface Client { credential: VisibleCredential; secret: Uint8Array }

const at = '2026-09-01T00:00:00.000Z'
const roomId = 'mimi://example.test/r/e2e'

/** Store.ts's assertAddedCredentialsBackedByMls (§17-18) requires a newly
 * added participant's VisibleCredential to byte-match a real `add`
 * proposal's KeyPackage LeafNode in the same commit -- so any test that adds
 * a member via a genuine MLS commit must derive its MimiCredential from that
 * same KeyPackage, not from an unrelated ad-hoc keypair. */
function credentialFromKeyPackage(user: string, client: string, kp: KeyPackage): VisibleCredential {
  return { kind: 'visible', user, client, credential: encodeCredential(kp.leafNode.credential), signaturePublicKey: kp.leafNode.signaturePublicKey }
}

function client(user: string, fragment: string, marker: number): Client {
  const secret = ed25519.utils.randomSecretKey()
  return {
    secret,
    credential: { kind: 'visible', user, client: `${user}#${fragment}`, credential: new Uint8Array([marker]), signaturePublicKey: ed25519.getPublicKey(secret) },
  }
}

function signedUpdate(sender: Client, value: Parameters<typeof updateRoomSigningBytes>[0]) {
  return { ...value, signature: ed25519.sign(updateRoomSigningBytes(value), sender.secret) }
}

/** A structurally real MLS PublicMessage Commit. Signature validation belongs
 * to the MLS group clients; the hub parses its authenticated AppDataUpdate. */
function participantCommit(room: string, epoch: string, before: { user: string; roleIndex: number }[], after: { user: string; roleIndex: number }[], roomName?: string, frankingSignatureKey?: Uint8Array, frankingCredential = new TextEncoder().encode('https://mimi.test'), addKeyPackages: KeyPackage[] = []): Uint8Array {
  const proposals: { proposalOrRefType: 'proposal'; proposal: { proposalType: 'app_data_update'; appDataUpdate: { componentId: number; operation: 'update'; update: Uint8Array } } | { proposalType: 'add'; add: { keyPackage: KeyPackage } } }[] = [
    // A genuine add proposal per newly-added member's real KeyPackage --
    // required since store.ts's assertAddedCredentialsBackedByMls (§17-18)
    // now rejects a participant_list claim for anyone not backed by one.
    ...addKeyPackages.map(keyPackage => ({ proposalOrRefType: 'proposal' as const, proposal: { proposalType: 'add' as const, add: { keyPackage } } })),
    { proposalOrRefType: 'proposal' as const, proposal: { proposalType: 'app_data_update' as const, appDataUpdate: {
      componentId: 0x0022, operation: 'update' as const, update: encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: before.map((_value, index) => index), addedParticipants: after }),
    } } },
  ]
  if (roomName !== undefined) proposals.push({ proposalOrRefType: 'proposal' as const, proposal: { proposalType: 'app_data_update' as const, appDataUpdate: {
    componentId: 0x0023, operation: 'update' as const, update: encodeMimiRoomMetadata({ roomUri: room, roomName }),
  } } })
  if (frankingSignatureKey !== undefined) proposals.push({ proposalOrRefType: 'proposal' as const, proposal: { proposalType: 'app_data_update' as const, appDataUpdate: {
    componentId: 0x0021, operation: 'update' as const, update: encodeMimiFrankingAgent({ frankingSignatureKey, credential: frankingCredential }),
  } } })
  return encodeMlsMessage({
    version: 'mls10', wireformat: 'mls_public_message',
    publicMessage: {
      content: {
        groupId: new TextEncoder().encode(room), epoch: BigInt(epoch), sender: { senderType: 'member', leafIndex: 0 }, authenticatedData: new Uint8Array(), contentType: 'commit',
        commit: { proposals, path: undefined },
      },
      auth: { contentType: 'commit', signature: new Uint8Array(), confirmationTag: new Uint8Array() }, senderType: 'member', membershipTag: new Uint8Array(),
    },
  })
}

describe('MIMI Phase 0 HTTP flow', () => {
  test('allowExternalJoin lets an existing participant\'s new device fetch GroupInfo, but not a stranger', async () => {
    // There is no distinct 'self' mode: a Self Group deployment is this same
    // 'normal' code with allowExternalJoin turned on (PLAN_biset-mimi-server.md
    // §14/§18) -- availability isolation from third-party rooms is a
    // deployment/process choice, not a code-level mode.
    const owner = client('did:web:owner', 'phone', 9)
    const stranger = client('did:web:stranger', 'phone', 10)
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', allowExternalJoin: true })
    const externalJoinRoom = 'mimi://self.example/r/owner'
    const frankingKey = deployment.store.prepareFrankingKeys(externalJoinRoom).signingPublicKey
    const groupInfoBytes = new TextEncoder().encode('opaque genuine GroupInfo bytes')
    const ratchetTreeBytes = new TextEncoder().encode('opaque genuine ratchet_tree bytes')
    const initialUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: externalJoinRoom, sender: owner.credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(externalJoinRoom, '0', [], [{ user: owner.credential.user, roleIndex: 1 }], 'self', frankingKey), groupInfo: groupInfoBytes, ratchetTree: ratchetTreeBytes },
      initialState: { basePolicy: new Uint8Array(), participantList: { participants: [{ user: owner.credential.user, roleIndex: 1 }] }, memberCredentials: [owner.credential], metadata: { roomUri: externalJoinRoom, roomName: 'self' } },
      submittedAt: at,
    }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(externalJoinRoom)}`, encodeUpdateRoomRequestWire(signedUpdate(owner, initialUnsigned))))).status).toBe(200)

    const suite = await mlsSuite()
    const newDeviceHpke = await suite.hpke.generateKeyPair()
    const newDeviceHpkePublicKey = await suite.hpke.exportPublicKey(newDeviceHpke.publicKey)
    const newDevice = client('did:web:owner', 'laptop', 11) // same user URI as owner, brand-new device credential

    // The owner's own new device: authorized because its `user` matches an
    // existing participant, even though its device credential is brand new.
    const ownRequestUnsigned = { version: 1 as const, protocol: 'mls10' as const, cipherSuite: 1, requester: newDevice.credential, groupInfoPublicKey: newDeviceHpkePublicKey, requestedAt: at }
    const ownRequest = { ...ownRequestUnsigned, signature: ed25519.sign(groupInfoRequestSigningBytes(ownRequestUnsigned), newDevice.secret) }
    const ownResponse = await deployment.fetch(post(`/groupInfo/${encodeURIComponent(externalJoinRoom)}`, encodeGroupInfoRequestWire(ownRequest)))
    expect(ownResponse.status).toBe(200)
    const decoded = decodeGroupInfoResponseWire(await ownResponse.text())
    expect(decoded.status).toBe('success')
    expect(decoded.hubSenderSignatureKey).toEqual(frankingKey)
    expect(ed25519.verify(decoded.signature!, groupInfoResponseSigningBytes(decoded), decoded.hubSenderSignatureKey!)).toBe(true)
    const plaintext = await decryptWithLabel(newDeviceHpke.privateKey, 'GroupInfo and ratchet_tree encryption', new TextEncoder().encode(externalJoinRoom), decoded.encryptedGroupInfoAndTree!.kemOutput, decoded.encryptedGroupInfoAndTree!.ciphertext, suite.hpke)
    const bundle = decodeGroupInfoRatchetTreeBundle(plaintext)
    expect(bundle.groupInfo).toEqual(groupInfoBytes)
    expect(bundle.ratchetTree).toEqual(ratchetTreeBytes)

    // Fetching GroupInfo is only the first half of external join.  The
    // external committer has a new leaf key, so ordinary exact-credential
    // authorization cannot admit this first commit.  The self deployment
    // accepts precisely this signed commit for an already-participating user.
    const restoredOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('did:web:owner#restored-laptop') })
    const restored = {
      credential: credentialFromKeyPackage('did:web:owner', 'did:web:owner#restored-laptop', restoredOwn.publicPackage),
      secret: restoredOwn.privatePackage.signaturePrivateKey,
    }
    const externalCommitUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: externalJoinRoom, sender: restored.credential, epoch: '1',
      bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(externalJoinRoom, '1', [{ user: owner.credential.user, roleIndex: 1 }], [{ user: owner.credential.user, roleIndex: 1 }], undefined, undefined, undefined, [restoredOwn.publicPackage]) },
      stateUpdate: {
        participantList: { participants: [{ user: owner.credential.user, roleIndex: 1, clientIds: [owner.credential.client, restored.credential.client] }] },
        memberCredentials: [owner.credential, restored.credential],
      },
      submittedAt: at,
    }
    const externalCommit = { ...externalCommitUnsigned, signature: ed25519.sign(updateRoomSigningBytes(externalCommitUnsigned), restored.secret) }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(externalJoinRoom)}`, encodeUpdateRoomRequestWire(externalCommit)))).status).toBe(200)
    expect(deployment.store.room(externalJoinRoom)?.memberCredentials).toContainEqual(restored.credential)

    // A stranger (different user URI, never a participant): refused.
    const strangerRequestUnsigned = { version: 1 as const, protocol: 'mls10' as const, cipherSuite: 1, requester: stranger.credential, groupInfoPublicKey: newDeviceHpkePublicKey, requestedAt: at }
    const strangerRequest = { ...strangerRequestUnsigned, signature: ed25519.sign(groupInfoRequestSigningBytes(strangerRequestUnsigned), stranger.secret) }
    const strangerResponse = await deployment.fetch(post(`/groupInfo/${encodeURIComponent(externalJoinRoom)}`, encodeGroupInfoRequestWire(strangerRequest)))
    expect(decodeGroupInfoResponseWire(await strangerResponse.text()).status).toBe('notAuthorized')

    // A room that doesn't exist.
    const noSuchRoomResponse = await deployment.fetch(post(`/groupInfo/${encodeURIComponent('mimi://self.example/r/does-not-exist')}`, encodeGroupInfoRequestWire(strangerRequest)))
    expect(decodeGroupInfoResponseWire(await noSuchRoomResponse.text()).status).toBe('noSuchRoom')
    deployment.close()
  })

  test('anon mode rejects a visible-credential room creation before it can reach storage', async () => {
    const alice = client('did:web:alice', 'phone', 1)
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'anon' })
    const unsigned = { version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '0', bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(roomId, '0', [], [{ user: alice.credential.user, roleIndex: 1 }], 'reject') }, initialState: { basePolicy: new Uint8Array(), participantList: { participants: [{ user: alice.credential.user, roleIndex: 1 }] }, memberCredentials: [alice.credential], metadata: { roomUri: roomId, roomName: 'reject' } }, submittedAt: at }
    const response = await deployment.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, unsigned))))
    expect(response.status).toBe(403)
    expect(deployment.store.room(roomId)).toBeUndefined()
    deployment.close()
  })

  test('groupInfo is explicitly forbidden because external join leaks GroupInfo membership', async () => {
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal' })
    const response = await deployment.fetch(post(`/groupInfo/${encodeURIComponent(roomId)}`, '{}'))
    expect(response.status).toBe(403)
    deployment.close()
  })

  test('creator obtains the hub franking public key before committing it into GroupContext', async () => {
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', publicBaseUrl: 'https://mimi.example.test' })
    const response = await deployment.fetch(new Request(`http://local/v1/mimi/franking-agent/${encodeURIComponent(roomId)}`))
    expect(response.status).toBe(200)
    expect(decodeFrankingAgentDataWire(await response.text()).frankingSignatureKey).toEqual(deployment.store.prepareFrankingKeys(roomId).signingPublicKey)
    deployment.close()
  })

  test('accepts signed MLS commits which create a room and add a member through MIMI AppData', async () => {
    const alice = client('did:web:alice-live', 'phone', 41)
    const bobUser = 'did:web:bob-live'
    const bobClient = `${bobUser}#laptop`
    const liveRoom = 'mimi://example.test/r/genuine-mls-wire'
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', publicBaseUrl: 'https://mimi.example.test' })
    const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(alice.credential.client) })
    const bobOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(bobClient) })
    // Bob's MimiCredential is derived from his real KeyPackage's LeafNode
    // (not an unrelated ad-hoc keypair) -- store.ts's
    // assertAddedCredentialsBackedByMls requires the two to match byte for
    // byte for a newly-added participant (§17-18).
    const bob = { credential: credentialFromKeyPackage(bobUser, bobClient, bobOwn.publicPackage) }
    const suite = await mlsSuite()
    let group = await createMlsGroup(new TextEncoder().encode(liveRoom), own)
    const proposal = (componentId: number, update: Uint8Array) => ({ proposalType: 'app_data_update' as const, appDataUpdate: { componentId, operation: 'update' as const, update } })
    const aliceParticipant = { user: alice.credential.user, roleIndex: 1, clientIds: [alice.credential.client] }
    const metadata = { roomUri: liveRoom, roomName: 'Genuine MLS wire room' }
    const initialCommit = await createCommit({ state: group, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [
        proposal(0x0021, encodeMimiFrankingAgent({ frankingSignatureKey: deployment.store.prepareFrankingKeys(liveRoom).signingPublicKey, credential: new TextEncoder().encode('https://mimi.example.test') })),
        proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [aliceParticipant] })),
        proposal(0x0023, encodeMimiRoomMetadata(metadata)),
      ],
    })
    const initialUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: liveRoom, sender: alice.credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(initialCommit.commit) },
      initialState: { basePolicy: new Uint8Array(), participantList: { participants: [aliceParticipant] }, memberCredentials: [alice.credential], metadata }, submittedAt: at,
    }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(liveRoom)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, initialUnsigned))))).status).toBe(200)
    group = initialCommit.newState

    const both = [aliceParticipant, { user: bob.credential.user, roleIndex: 1, clientIds: [bob.credential.client] }]
    const addCommit = await createCommit({ state: group, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [
        { proposalType: 'add' as const, add: { keyPackage: bobOwn.publicPackage } },
        proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [{ user: bob.credential.user, roleIndex: 1 }] })),
      ],
    })
    const addUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: liveRoom, sender: alice.credential, epoch: '1',
      bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(addCommit.commit), welcome: encodeWelcome(addCommit.welcome!) },
      stateUpdate: { participantList: { participants: both }, memberCredentials: [alice.credential, bob.credential] }, submittedAt: '2026-09-01T00:00:01.000Z',
    }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(liveRoom)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, addUnsigned))))).status).toBe(200)
    expect(deployment.store.room(liveRoom)?.participantList.participants.map(({ user, roleIndex }) => ({ user, roleIndex }))).toEqual(both.map(({ user, roleIndex }) => ({ user, roleIndex })))
    deployment.close()
  })

  test('anon mode accepts a pseudonymous room creation and subsequent commit without a visible identifier', async () => {
    const secret = ed25519.utils.randomSecretKey()
    const bobSecret = ed25519.utils.randomSecretKey()
    const epochOne = { async exportSecret() { return new Uint8Array(32).fill(1) } }
    const epochTwo = { async exportSecret() { return new Uint8Array(32).fill(2) } }
    const encoder = new TextEncoder()
    const decoder = new TextDecoder()
    const credential: PseudonymousCredential = {
      kind: 'pseudonymous',
      userPseudonym: 'mimi://anon.example/u/8e1d21d4-2ebd-4b7c-9d35-16a8fb355d09',
      clientPseudonym: 'mimi://anon.example/c/5d6e5eeb-ed84-46fd-a2a8-66f79d23dfcf',
      signaturePublicKey: ed25519.getPublicKey(secret),
      identityLinkCiphertext: await encryptIdentityLink(epochOne, 'mimi://anon.example/r/opaque-room', encoder.encode('did:web:alice')),
    }
    const bob: PseudonymousCredential = {
      kind: 'pseudonymous',
      userPseudonym: 'mimi://anon.example/u/38079f19-c42a-4e4e-bf31-7cd903a06c2a',
      clientPseudonym: 'mimi://anon.example/c/2cebc41f-73fb-4e99-ad88-ddaf6cb31e5d',
      signaturePublicKey: ed25519.getPublicKey(bobSecret),
      identityLinkCiphertext: await encryptIdentityLink(epochTwo, 'mimi://anon.example/r/opaque-room', encoder.encode('did:web:bob')),
    }
    const anonRoomId = 'mimi://anon.example/r/opaque-room'
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'anon' })
    const frankingSignatureKey = deployment.store.prepareFrankingKeys(anonRoomId).signingPublicKey
    const initialUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: anonRoomId, sender: credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(anonRoomId, '0', [], [{ user: credential.userPseudonym, roleIndex: 1 }], 'opaque', frankingSignatureKey) },
      initialState: {
        basePolicy: new Uint8Array(), participantList: { participants: [{ user: credential.userPseudonym, roleIndex: 1, clientIds: [credential.clientPseudonym] }] },
        memberCredentials: [credential], metadata: { roomUri: anonRoomId, roomName: 'opaque' },
      }, submittedAt: at,
    }
    const initial = { ...initialUnsigned, signature: ed25519.sign(updateRoomSigningBytes(initialUnsigned), secret) }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(anonRoomId)}`, encodeUpdateRoomRequestWire(initial)))).status).toBe(200)

    const aliceAtEpochTwo = { ...credential, identityLinkCiphertext: await encryptIdentityLink(epochTwo, anonRoomId, encoder.encode('did:web:alice')) }
    const addUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: anonRoomId, sender: credential, epoch: '1',
      bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(anonRoomId, '1', [{ user: credential.userPseudonym, roleIndex: 1 }], [{ user: credential.userPseudonym, roleIndex: 1 }, { user: bob.userPseudonym, roleIndex: 1 }]), welcome: new Uint8Array([3]) },
      stateUpdate: {
        participantList: { participants: [{ user: credential.userPseudonym, roleIndex: 1 }, { user: bob.userPseudonym, roleIndex: 1, clientIds: [bob.clientPseudonym] }] },
        memberCredentials: [aliceAtEpochTwo, bob],
      }, submittedAt: at,
    }
    const add = { ...addUnsigned, signature: ed25519.sign(updateRoomSigningBytes(addUnsigned), secret) }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(anonRoomId)}`, encodeUpdateRoomRequestWire(add)))).status).toBe(200)
    const joinedCredentials = deployment.store.room(anonRoomId)?.memberCredentials ?? []
    expect(await Promise.all(joinedCredentials.map(item => decryptIdentityLink(epochTwo, anonRoomId, item.identityLinkCiphertext).then(bytes => decoder.decode(bytes))))).toEqual(['did:web:alice', 'did:web:bob'])
    await expect(decryptIdentityLink(epochOne, anonRoomId, aliceAtEpochTwo.identityLinkCiphertext)).rejects.toThrow()

    const pullUnsigned = { version: 1 as const, roomId: anonRoomId, requester: credential, afterSeq: 0, requestedAt: at }
    const pull = { ...pullUnsigned, signature: ed25519.sign(deliveriesPullSigningBytes(pullUnsigned), secret) }
    const pulled = await deployment.fetch(post('/v1/mimi/deliveries/pull', encodeDeliveriesPullRequestWire(pull)))
    expect(pulled.status).toBe(200)
    expect(decodeDeliveriesWire(await pulled.text()).map(entry => entry.kind)).toEqual(['commit', 'welcome', 'commit'])

    const watchUnsigned = { version: 1 as const, roomId: anonRoomId, requester: credential, requestedAt: at }
    const watch = { ...watchUnsigned, signature: ed25519.sign(deliveriesWatchSigningBytes(watchUnsigned), secret) }
    expect((await deployment.fetch(post('/v1/mimi/deliveries/watch', encodeDeliveriesWatchRequestWire(watch)))).status).toBe(200)

    const messageUnsigned = { version: 1 as const, protocol: 'mls10' as const, roomId: anonRoomId, sender: credential, epoch: '2', appMessage: new Uint8Array([5]), frankAAD: { frankingTag: new Uint8Array(32).fill(7) }, frankingSignatureCiphersuite: 1, submittedAt: at }
    const message = { ...messageUnsigned, signature: ed25519.sign(submitMessageSigningBytes(messageUnsigned), secret) }
    expect((await deployment.fetch(post(`/submitMessage/${encodeURIComponent(anonRoomId)}`, encodeSubmitMessageRequestWire(message)))).status).toBe(200)
    const afterMessage = { ...pullUnsigned, afterSeq: 3 }
    const afterMessageSigned = { ...afterMessage, signature: ed25519.sign(deliveriesPullSigningBytes(afterMessage), secret) }
    expect(decodeDeliveriesWire(await (await deployment.fetch(post('/v1/mimi/deliveries/pull', encodeDeliveriesPullRequestWire(afterMessageSigned)))).text()).map(entry => entry.kind)).toEqual(['application'])

    const removeUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: anonRoomId, sender: credential, epoch: '2',
      bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(anonRoomId, '2', [{ user: credential.userPseudonym, roleIndex: 1 }, { user: bob.userPseudonym, roleIndex: 1 }], [{ user: credential.userPseudonym, roleIndex: 1 }]) },
      stateUpdate: { participantList: { participants: [{ user: credential.userPseudonym, roleIndex: 1 }] }, memberCredentials: [aliceAtEpochTwo] }, submittedAt: at,
    }
    const remove = { ...removeUnsigned, signature: ed25519.sign(updateRoomSigningBytes(removeUnsigned), secret) }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(anonRoomId)}`, encodeUpdateRoomRequestWire(remove)))).status).toBe(200)
    expect(deployment.store.room(anonRoomId)?.memberCredentials).toEqual([aliceAtEpochTwo])
    deployment.close()
  })

  test('three clients create, add, claim KeyPackages, then receive a commit through biset delivery APIs', async () => {
    const alice = client('did:web:alice', 'phone', 1)
    // Bob and Charlie are added via real MLS `add` proposals below, so their
    // MimiCredential (and the private key that signs their own later
    // requests) must be derived from real KeyPackages -- assertAddedCredentialsBackedByMls
    // (§17-18) checks this by matching bytes, not just trusting the sidecar.
    const bobOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('did:web:bob#laptop') })
    const charlieOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('did:web:charlie#tablet') })
    const bob = { credential: credentialFromKeyPackage('did:web:bob', 'did:web:bob#laptop', bobOwn.publicPackage), secret: bobOwn.privatePackage.signaturePrivateKey }
    const charlie = { credential: credentialFromKeyPackage('did:web:charlie', 'did:web:charlie#tablet', charlieOwn.publicPackage), secret: charlieOwn.privatePackage.signaturePrivateKey }
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal' })
    const frankingSignatureKey = deployment.store.prepareFrankingKeys(roomId).signingPublicKey

    const initialUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(roomId, '0', [], [{ user: alice.credential.user, roleIndex: 1 }], 'Three devices', frankingSignatureKey) },
      initialState: {
        basePolicy: new Uint8Array(), participantList: { participants: [{ user: alice.credential.user, roleIndex: 1, clientIds: [alice.credential.client] }] },
        memberCredentials: [alice.credential], metadata: { roomUri: roomId, roomName: 'Three devices' },
      }, submittedAt: at,
    }
    const created = await deployment.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, initialUnsigned))))
    expect(created.status).toBe(200)
    expect(decodeUpdateRoomResponseWire(await created.text()).status).toBe('success')

    // Real clients can only ever reach the store through this HTTP route --
    // it does not exist in the MIMI draft, and its absence was found live
    // (2026-09-01): keyMaterial always returned noCompatibleMaterial because
    // nothing could ever publish into it.
    const bobPublishUnsigned = {
      version: 1, credential: bob.credential,
      packages: [{ reference: new Uint8Array([10]), user: bob.credential.user, client: bob.credential.client, keyPackage: new Uint8Array([11]), publishedAt: at }], publishedAt: at,
    }
    const bobPublish = { ...bobPublishUnsigned, signature: ed25519.sign(keyPackagePublishSigningBytes(bobPublishUnsigned), bob.secret) }
    expect(await authorizeKeyPackagePublish({ verify: async (credential, bytes, signature) => ed25519.verify(signature, bytes, credential.signaturePublicKey) }, bobPublish)).toBe(true)
    const bobPublishResponse = await deployment.fetch(post('/v1/mimi/keypackage/publish', encodeKeyPackagePublishWire(bobPublish)))
    expect(bobPublishResponse.status).toBe(200)
    expect(decodeKeyPackagePublishResponseWire(await bobPublishResponse.text())).toEqual({ published: 1 })

    const charliePublishUnsigned = {
      version: 1, credential: charlie.credential,
      packages: [{ reference: new Uint8Array([12]), user: charlie.credential.user, client: charlie.credential.client, keyPackage: new Uint8Array([13]), publishedAt: at }], publishedAt: at,
    }
    const charliePublish = { ...charliePublishUnsigned, signature: ed25519.sign(keyPackagePublishSigningBytes(charliePublishUnsigned), charlie.secret) }
    expect((await deployment.fetch(post('/v1/mimi/keypackage/publish', encodeKeyPackagePublishWire(charliePublish)))).status).toBe(200)

    // A forged publish (wrong signer) must be rejected, not silently stored.
    const forgedPublish = { ...charliePublishUnsigned, signature: ed25519.sign(keyPackagePublishSigningBytes(charliePublishUnsigned), bob.secret) }
    expect((await deployment.fetch(post('/v1/mimi/keypackage/publish', encodeKeyPackagePublishWire(forgedPublish)))).status).toBe(403)

    const bobMaterial = await requestKeyMaterial(deployment.fetch, alice, bob.credential.user)
    expect(bobMaterial.clients).toEqual([{ client: bob.credential.client, status: 'success', keyPackage: new Uint8Array([11]), capabilities: undefined }])

    const addBobUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '1',
      bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(roomId, '1', [{ user: alice.credential.user, roleIndex: 1 }], [{ user: alice.credential.user, roleIndex: 1 }, { user: bob.credential.user, roleIndex: 1 }], undefined, undefined, undefined, [bobOwn.publicPackage]), welcome: new Uint8Array([3]) },
      stateUpdate: {
        participantList: { participants: [{ user: alice.credential.user, roleIndex: 1, clientIds: [alice.credential.client] }, { user: bob.credential.user, roleIndex: 1, clientIds: [bob.credential.client] }] },
        memberCredentials: [alice.credential, bob.credential],
      }, submittedAt: at,
    }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, addBobUnsigned))))).status).toBe(200)

    const charlieMaterial = await requestKeyMaterial(deployment.fetch, bob, charlie.credential.user)
    expect(charlieMaterial.clients[0]?.keyPackage).toEqual(new Uint8Array([13]))

    const addCharlieUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: bob.credential, epoch: '2',
      bundle: { kind: 'commit' as const, proposalOrCommit: participantCommit(roomId, '2', [{ user: alice.credential.user, roleIndex: 1 }, { user: bob.credential.user, roleIndex: 1 }], [{ user: alice.credential.user, roleIndex: 1 }, { user: bob.credential.user, roleIndex: 1 }, { user: charlie.credential.user, roleIndex: 1 }], undefined, undefined, undefined, [charlieOwn.publicPackage]), welcome: new Uint8Array([5]) },
      stateUpdate: {
        participantList: { participants: [{ user: alice.credential.user, roleIndex: 1 }, { user: bob.credential.user, roleIndex: 1 }, { user: charlie.credential.user, roleIndex: 1, clientIds: [charlie.credential.client] }] },
        memberCredentials: [alice.credential, bob.credential, charlie.credential],
      }, submittedAt: at,
    }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(bob, addCharlieUnsigned))))).status).toBe(200)

    const pullUnsigned = { version: 1 as const, roomId, requester: charlie.credential, afterSeq: 0, requestedAt: at }
    const pull = { ...pullUnsigned, signature: ed25519.sign(deliveriesPullSigningBytes(pullUnsigned), charlie.secret) }
    const pullResponse = await deployment.fetch(post('/v1/mimi/deliveries/pull', encodeDeliveriesPullRequestWire(pull)))
    expect(pullResponse.status).toBe(200)
    expect(decodeDeliveriesWire(await pullResponse.text()).map(entry => entry.kind)).toEqual(['commit', 'welcome', 'commit', 'welcome', 'commit'])

    const watchUnsigned = { version: 1 as const, roomId, requester: charlie.credential, requestedAt: at }
    const watch = { ...watchUnsigned, signature: ed25519.sign(deliveriesWatchSigningBytes(watchUnsigned), charlie.secret) }
    const watchResponse = await deployment.fetch(post('/v1/mimi/deliveries/watch', encodeDeliveriesWatchRequestWire(watch)))
    const { token } = await watchResponse.json() as { token: string }
    expect(watchResponse.status).toBe(200)

    const stream = await deployment.fetch(new Request(`https://mimi.test/v1/mimi/deliveries/stream?token=${token}&afterSeq=5`))
    expect(stream.status).toBe(200)
    const reader = stream.body!.getReader()
    const first = await reader.read()
    expect(new TextDecoder().decode(first.value)).toContain(': connected')

    const proposalUnsigned = { version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '3', bundle: { kind: 'proposal' as const, proposalOrCommit: new Uint8Array([6]) }, submittedAt: at }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, proposalUnsigned))))).status).toBe(200)
    const live = await reader.read()
    expect(new TextDecoder().decode(live.value)).toContain('"kind":"proposal"')

    const messageUnsigned = { version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '3', appMessage: new Uint8Array([7, 8]), frankAAD: { frankingTag: new Uint8Array(32).fill(9) }, frankingSignatureCiphersuite: 1, submittedAt: at }
    const message = { ...messageUnsigned, signature: ed25519.sign(submitMessageSigningBytes(messageUnsigned), alice.secret) }
    const messageResponse = await deployment.fetch(post(`/submitMessage/${encodeURIComponent(roomId)}`, encodeSubmitMessageRequestWire(message)))
    expect(messageResponse.status).toBe(200)
    const accepted = await messageResponse.json() as { status: string; frank?: unknown }
    expect(accepted.status).toBe('accepted')
    expect(decodeFrankWire(JSON.stringify(accepted.frank)).serverFrank).toHaveLength(32)
    const frankedLive = await reader.read()
    expect(new TextDecoder().decode(frankedLive.value)).toContain('"kind":"application"')

    const malformed = JSON.parse(encodeSubmitMessageRequestWire(message)) as Record<string, unknown>
    delete malformed.frankAAD
    expect((await deployment.fetch(post(`/submitMessage/${encodeURIComponent(roomId)}`, JSON.stringify(malformed)))).status).toBe(400)
    await reader.cancel()
    expect(deployment.store.subscriberCount(roomId)).toBe(0)
    deployment.close()
  })
})

async function requestKeyMaterial(fetch: (request: Request) => Promise<Response>, requester: Client, targetUser: string) {
  const unsigned = { version: 1 as const, protocol: 'mls10' as const, requestingUser: requester.credential.user, targetUser, roomId, acceptableCiphersuites: [1], requiredCapabilities: {}, requester: requester.credential }
  const value = { ...unsigned, signature: ed25519.sign(keyMaterialSigningBytes(unsigned), requester.secret) }
  const response = await fetch(post(`/keyMaterial/${encodeURIComponent(targetUser)}`, encodeKeyMaterialRequestWire(value)))
  expect(response.status).toBe(200)
  return decodeKeyMaterialResponseWire(await response.text())
}

function post(path: string, body: string): Request {
  return new Request(`https://mimi.test${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
}
