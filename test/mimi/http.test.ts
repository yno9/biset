import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createMimiDeployment } from '../../src/mimi/deployment.ts'
import { decryptIdentityLink, encryptIdentityLink } from '../../src/mimi/anon/identity-link.ts'
import {
  deliveriesPullSigningBytes,
  deliveriesWatchSigningBytes,
  authorizeKeyPackagePublish,
  keyPackagePublishSigningBytes,
  keyMaterialSigningBytes,
  submitMessageSigningBytes,
  updateRoomSigningBytes,
} from '../../src/mimi/authorizer.ts'
import {
  decodeDeliveriesWire,
  decodeKeyMaterialResponseWire,
  decodeKeyPackagePublishResponseWire,
  decodeUpdateRoomResponseWire,
  encodeDeliveriesPullRequestWire,
  encodeDeliveriesWatchRequestWire,
  encodeKeyMaterialRequestWire,
  encodeKeyPackagePublishWire,
  decodeFrankWire,
  encodeSubmitMessageRequestWire,
  encodeUpdateRoomRequestWire,
} from '../../src/mimi/wire.ts'
import type { PseudonymousCredential, VisibleCredential } from '../../src/mimi/protocol-types.ts'

interface Client { credential: VisibleCredential; secret: Uint8Array }

const at = '2026-09-01T00:00:00.000Z'
const roomId = 'mimi://example.test/r/e2e'

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

describe('MIMI Phase 0 HTTP flow', () => {
  test('self mode requires one owner, rejects another visible identity, and exposes no federation routes', async () => {
    const owner = client('did:web:owner', 'phone', 9)
    const other = client('did:web:other', 'phone', 10)
    expect(() => createMimiDeployment({ databasePath: ':memory:', mode: 'self' })).toThrow('selfOwnerUser')
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'self', selfOwnerUser: owner.credential.user })
    const unsigned = (sender: Client, id: string) => ({ version: 1 as const, protocol: 'mls10' as const, roomId: id, sender: sender.credential, epoch: '0', bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([1]) }, initialState: { basePolicy: new Uint8Array(), participantList: { participants: [{ user: sender.credential.user, roleIndex: 1 }] }, memberCredentials: [sender.credential], metadata: { roomUri: id, roomName: 'self' } }, submittedAt: at })
    const own = unsigned(owner, 'mimi://self.example/r/owner')
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(own.roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(owner, own))))).status).toBe(200)
    const rejected = unsigned(other, 'mimi://self.example/r/other')
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(rejected.roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(other, rejected))))).status).toBe(403)
    expect((await deployment.fetch(post('/requestConsent/self.example', '{}'))).status).toBe(403)
    deployment.close()
  })

  test('anon mode rejects a visible-credential room creation before it can reach storage', async () => {
    const alice = client('did:web:alice', 'phone', 1)
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'anon' })
    const unsigned = { version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '0', bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([1]) }, initialState: { basePolicy: new Uint8Array(), participantList: { participants: [{ user: alice.credential.user, roleIndex: 1 }] }, memberCredentials: [alice.credential], metadata: { roomUri: roomId, roomName: 'reject' } }, submittedAt: at }
    const response = await deployment.fetch(post(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire(signedUpdate(alice, unsigned))))
    expect(response.status).toBe(403)
    expect(deployment.store.room(roomId)).toBeUndefined()
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
    const initialUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: anonRoomId, sender: credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([1]) },
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
      bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([2]), welcome: new Uint8Array([3]) },
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
      bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([4]) },
      stateUpdate: { participantList: { participants: [{ user: credential.userPseudonym, roleIndex: 1 }] }, memberCredentials: [aliceAtEpochTwo] }, submittedAt: at,
    }
    const remove = { ...removeUnsigned, signature: ed25519.sign(updateRoomSigningBytes(removeUnsigned), secret) }
    expect((await deployment.fetch(post(`/update/${encodeURIComponent(anonRoomId)}`, encodeUpdateRoomRequestWire(remove)))).status).toBe(200)
    expect(deployment.store.room(anonRoomId)?.memberCredentials).toEqual([aliceAtEpochTwo])
    deployment.close()
  })

  test('three clients create, add, claim KeyPackages, then receive a commit through biset delivery APIs', async () => {
    const alice = client('did:web:alice', 'phone', 1)
    const bob = client('did:web:bob', 'laptop', 2)
    const charlie = client('did:web:charlie', 'tablet', 3)
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal' })

    const initialUnsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId, sender: alice.credential, epoch: '0',
      bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([1]) },
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
      bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([2]), welcome: new Uint8Array([3]) },
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
      bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([4]), welcome: new Uint8Array([5]) },
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
