import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createMimiDeployment } from '../../src/mimi/deployment.ts'
import { MimiFanoutDispatcher } from '../../src/mimi/fanout.ts'
import { MimiProviderTransport } from '../../src/mimi/provider-transport.ts'
import { updateRoomSigningBytes, submitMessageSigningBytes } from '../../src/mimi/authorizer.ts'
import { encodeUpdateRoomRequestWire, encodeSubmitMessageRequestWire } from '../../src/mimi/wire.ts'
import { encodeMimiFrankingAgent, encodeMimiParticipantListUpdate, encodeMimiRoomMetadata } from '../../src/mimi/app-data.ts'
import { createMlsGroup, generateOwnKeyPackageForCredential } from '../../src/mls/group.ts'
import { mlsSuite } from '../../src/vendor/mls/suite.ts'
import { createApplicationMessage, createCommit, encodeMlsMessage, type KeyPackage } from '../../src/vendor/mls/index.ts'
import { encodeCredential } from '../../src/vendor/mls/credential.ts'
import { encodeWelcome } from '../../src/vendor/mls/welcome.ts'
import type { VisibleCredential } from '../../src/mimi/protocol-types.ts'

const at = '2026-09-01T00:00:00.000Z'
const roomId = 'mimi://hub.example/r/cross-provider'

function credentialFromKeyPackage(user: string, client: string, kp: KeyPackage): VisibleCredential {
  return { kind: 'visible', user, client, credential: encodeCredential(kp.leafNode.credential), signaturePublicKey: kp.leafNode.signaturePublicKey }
}

interface Client { credential: VisibleCredential; secret: Uint8Array }
function client(user: string, fragment: string, marker: number): Client {
  const secret = ed25519.utils.randomSecretKey()
  return { secret, credential: { kind: 'visible', user, client: `${user}#${fragment}`, credential: new Uint8Array([marker]), signaturePublicKey: ed25519.getPublicKey(secret) } }
}

function signedUpdate(sender: Client, value: Parameters<typeof updateRoomSigningBytes>[0]) {
  return { ...value, signature: ed25519.sign(updateRoomSigningBytes(value), sender.secret) }
}

/** A transport whose "network" is a direct in-process call into the target
 * deployment's own fetch handler -- mirrors federation-gate.test.ts's
 * pattern, avoiding a real TLS/HTTP round trip for this test. */
function directTransport(sourceProviderDomain: string, target: { fetch: (request: Request) => Promise<Response> }): MimiProviderTransport {
  return new MimiProviderTransport({
    sourceProviderDomain, tls: { cert: 'test-cert', key: 'test-key' },
    fetchImpl: async (input, init) => { const { tls: _tls, ...requestInit } = init ?? {}; return target.fetch(new Request(input, requestInit)) },
  })
}

describe('MIMI federation outbound dispatch (automatic, not manually triggered)', () => {
  test('room creation with a remote member, and a later application message, both reach the remote provider without an explicit fanout call', async () => {
    const alice = client('mimi://hub.example/u/alice', 'phone', 41)
    const bobUser = 'mimi://follower.example/u/bob'
    const bobClient = `${bobUser}#laptop`
    const follower = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', federation: { providerDomain: 'follower.example', authenticatePeer: async () => ({ providerDomain: 'hub.example' }) } })
    const hub = createMimiDeployment({
      databasePath: ':memory:', mode: 'normal', publicBaseUrl: 'https://mimi.hub.example',
      federation: {
        providerDomain: 'hub.example',
        authenticatePeer: async () => undefined,
        outbound: { dispatcher: new MimiFanoutDispatcher(directTransport('hub.example', follower)), resolveProviderBaseUrl: async domain => `https://${domain}` },
      },
    })

    const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(alice.credential.client) })
    const bobOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(bobClient) })
    const bob = { credential: credentialFromKeyPackage(bobUser, bobClient, bobOwn.publicPackage) }
    const suite = await mlsSuite()
    let group = await createMlsGroup(new TextEncoder().encode(roomId), own)
    const proposal = (componentId: number, update: Uint8Array) => ({ proposalType: 'app_data_update' as const, appDataUpdate: { componentId, operation: 'update' as const, update } })
    const aliceParticipant = { user: alice.credential.user, roleIndex: 1, clientIds: [alice.credential.client] }
    const metadata = { roomUri: roomId, roomName: 'cross-provider' }

    const initialCommit = await createCommit({ state: group, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [
        proposal(0x0021, encodeMimiFrankingAgent({ frankingSignatureKey: hub.store.prepareFrankingKeys(roomId).signingPublicKey, credential: new TextEncoder().encode('https://mimi.hub.example') })),
        proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [aliceParticipant] })),
        proposal(0x0023, encodeMimiRoomMetadata(metadata)),
      ],
    })
    const initialUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(initialCommit.commit) },
      initialState: { basePolicy: new Uint8Array(), participantList: { participants: [aliceParticipant] }, memberCredentials: [alice.credential], metadata }, submittedAt: at,
    }
    expect((await hub.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, initialUnsigned))))).status).toBe(200)
    group = initialCommit.newState

    // /notify (store.ts's acceptProviderFanout) only accepts fanout for a
    // room it already has a row for -- it does not bootstrap a brand-new
    // room from federated input (a real, separate gap from outbound
    // dispatch itself, flagged in PLAN_biset-mimi-server.md's federation
    // worksheet). Seed the same room on the follower directly via the
    // low-level store API (bypassing http.ts's franking-credential-matches-
    // my-own-origin check, which assumes the caller IS the room's home hub
    // -- not true for a follower mirroring someone else's room), mirroring
    // federation-gate.test.ts's own setup. This isolates and proves only
    // the piece being added here: that dispatch fires automatically,
    // without the test calling it itself.
    expect(follower.store.submitUpdate(initialUnsigned, {
      participantListUpdates: [{ changedRoleParticipants: [], removedIndices: [], addedParticipants: [aliceParticipant] }],
      roomMetadata: metadata,
      frankingAgent: { frankingSignatureKey: follower.store.prepareFrankingKeys(roomId).signingPublicKey, credential: new Uint8Array() },
    }).ok).toBe(true)

    // Bob (mimi://follower.example/u/bob) is added -- a different provider
    // domain than the hub's own 'hub.example'. This commit+welcome must
    // reach `follower` automatically once /update accepts it locally --
    // the test never calls MimiFanoutDispatcher.send itself.
    const both = [aliceParticipant, { user: bob.credential.user, roleIndex: 1, clientIds: [bob.credential.client] }]
    const addCommit = await createCommit({ state: group, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [
        { proposalType: 'add' as const, add: { keyPackage: bobOwn.publicPackage } },
        proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [{ user: bob.credential.user, roleIndex: 1 }] })),
      ],
    })
    const addUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '1',
      // ratchetTree is stored/forwarded as opaque bytes (same "opaque blob"
      // treatment as GroupInfo's own ratchet_tree, group-info.ts) -- fanout's
      // own validation only requires ratchetTreeOption be present alongside
      // a Welcome, not that its bytes have any particular shape.
      bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(addCommit.commit), welcome: encodeWelcome(addCommit.welcome!), ratchetTree: new Uint8Array([9, 9, 9]) },
      stateUpdate: { participantList: { participants: both }, memberCredentials: [alice.credential, bob.credential] }, submittedAt: '2026-09-01T00:00:01.000Z',
    }
    expect((await hub.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, addUnsigned))))).status).toBe(200)

    // Fanout is fire-and-forget (never blocks the local /update response) --
    // give the detached promise chain a tick to settle.
    await new Promise(resolve => setTimeout(resolve, 20))

    const followerDeliveries = follower.store.deliveriesSince(roomId, alice.credential.user, 0) ?? []
    expect(followerDeliveries.some(entry => entry.kind === 'commit')).toBe(true)
    expect(followerDeliveries.some(entry => entry.kind === 'welcome')).toBe(true)

    // A later application message must also fan out automatically. fanout.ts
    // decodes `.message` to classify it (welcome/application/proposal/
    // commit), so this must be a genuinely valid MLSMessage -- unlike
    // http.test.ts's own submitMessage tests, which never exercise fanout
    // and so can get away with opaque placeholder bytes.
    group = addCommit.newState
    const encrypted = await createApplicationMessage(group, new TextEncoder().encode('hello bob'), suite)
    const submitUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '2',
      appMessage: encodeMlsMessage({ version: 'mls10' as const, wireformat: 'mls_private_message' as const, privateMessage: encrypted.privateMessage }),
      frankAAD: { frankingTag: new Uint8Array(32).fill(7) }, frankingSignatureCiphersuite: 1, submittedAt: '2026-09-01T00:00:02.000Z',
    }
    const submitResponse = await hub.fetch(post(`/submitMessage/${encodeURIComponent(roomId)}`, encodeSubmitMessageRequestWire({ ...submitUnsigned, signature: ed25519.sign(submitMessageSigningBytes(submitUnsigned), alice.secret) })))
    expect(submitResponse.status).toBe(200)
    await new Promise(resolve => setTimeout(resolve, 20))
    expect((follower.store.deliveriesSince(roomId, alice.credential.user, 0) ?? []).some(entry => entry.kind === 'application')).toBe(true)

    hub.close(); follower.close()
  })

  test('a genesis commit that already includes a remote member bootstraps the room on the follower with no manual seeding', async () => {
    const genesisRoomId = 'mimi://hub.example/r/genesis-with-remote-member'
    const alice = client('mimi://hub.example/u/alice', 'phone', 51)
    const bobUser = 'mimi://follower.example/u/bob'
    const bobClient = `${bobUser}#laptop`
    const follower = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', federation: { providerDomain: 'follower.example', authenticatePeer: async () => ({ providerDomain: 'hub.example' }) } })
    const hub = createMimiDeployment({
      databasePath: ':memory:', mode: 'normal', publicBaseUrl: 'https://mimi.hub.example',
      federation: {
        providerDomain: 'hub.example',
        authenticatePeer: async () => undefined,
        outbound: { dispatcher: new MimiFanoutDispatcher(directTransport('hub.example', follower)), resolveProviderBaseUrl: async domain => `https://${domain}` },
      },
    })

    const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(alice.credential.client) })
    const bobOwn = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(bobClient) })
    const bob = { credential: credentialFromKeyPackage(bobUser, bobClient, bobOwn.publicPackage) }
    const suite = await mlsSuite()
    const group = await createMlsGroup(new TextEncoder().encode(genesisRoomId), own)
    const proposal = (componentId: number, update: Uint8Array) => ({ proposalType: 'app_data_update' as const, appDataUpdate: { componentId, operation: 'update' as const, update } })
    const aliceParticipant = { user: alice.credential.user, roleIndex: 1, clientIds: [alice.credential.client] }
    const bobParticipant = { user: bob.credential.user, roleIndex: 1, clientIds: [bob.credential.client] }
    const metadata = { roomUri: genesisRoomId, roomName: 'genesis with remote member' }

    // Bob is an *initial* member here -- his `add` proposal rides the same
    // genesis commit as room_metadata/franking_signature_key, so the
    // fanned-out commit is self-sufficient bootstrap material for the
    // follower (store.ts's createFromProviderFanout's documented scope).
    const genesisCommit = await createCommit({ state: group, cipherSuite: suite }, {
      wireAsPublicMessage: true,
      extraProposals: [
        { proposalType: 'add' as const, add: { keyPackage: bobOwn.publicPackage } },
        proposal(0x0021, encodeMimiFrankingAgent({ frankingSignatureKey: hub.store.prepareFrankingKeys(genesisRoomId).signingPublicKey, credential: new TextEncoder().encode('https://mimi.hub.example') })),
        proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [aliceParticipant, bobParticipant] })),
        proposal(0x0023, encodeMimiRoomMetadata(metadata)),
      ],
    })
    const genesisUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: genesisRoomId, sender: alice.credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(genesisCommit.commit), welcome: encodeWelcome(genesisCommit.welcome!), ratchetTree: new Uint8Array([9, 9, 9]) },
      initialState: { basePolicy: new Uint8Array(), participantList: { participants: [aliceParticipant, bobParticipant] }, memberCredentials: [alice.credential, bob.credential], metadata }, submittedAt: at,
    }

    expect(follower.store.room(genesisRoomId)).toBeUndefined()
    expect((await hub.fetch(post(`/update/${encodeURIComponent(genesisRoomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, genesisUnsigned))))).status).toBe(200)
    await new Promise(resolve => setTimeout(resolve, 20))

    const bootstrapped = follower.store.room(genesisRoomId)
    expect(bootstrapped).toBeDefined()
    expect(bootstrapped?.participantList.participants.map(p => p.user).sort()).toEqual([alice.credential.user, bob.credential.user].sort())
    expect(bootstrapped?.metadata.roomName).toBe('genesis with remote member')

    hub.close(); follower.close()
  })
})

function post(path: string, body: string): Request {
  return new Request(`https://mimi.test${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
}
