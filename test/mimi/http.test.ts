import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createMimiDeployment } from '../../src/mimi/deployment.ts'
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
  decodeUpdateRoomResponseWire,
  encodeDeliveriesPullRequestWire,
  encodeDeliveriesWatchRequestWire,
  encodeKeyMaterialRequestWire,
  decodeFrankWire,
  encodeSubmitMessageRequestWire,
  encodeUpdateRoomRequestWire,
} from '../../src/mimi/wire.ts'
import type { VisibleCredential } from '../../src/mimi/protocol-types.ts'

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
  test('three clients create, add, claim KeyPackages, then receive a commit through biset delivery APIs', async () => {
    const alice = client('did:web:alice', 'phone', 1)
    const bob = client('did:web:bob', 'laptop', 2)
    const charlie = client('did:web:charlie', 'tablet', 3)
    const deployment = createMimiDeployment({ databasePath: ':memory:' })

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

    const bobPublishUnsigned = {
      version: 1, credential: bob.credential,
      packages: [{ reference: new Uint8Array([10]), user: bob.credential.user, client: bob.credential.client, keyPackage: new Uint8Array([11]), publishedAt: at }], publishedAt: at, signature: new Uint8Array(),
    }
    const bobPublish = { ...bobPublishUnsigned, signature: ed25519.sign(keyPackagePublishSigningBytes(bobPublishUnsigned), bob.secret) }
    expect(await authorizeKeyPackagePublish({ verify: async (credential, bytes, signature) => ed25519.verify(signature, bytes, credential.signaturePublicKey) }, bobPublish)).toBe(true)
    deployment.store.publishKeyPackages(bobPublish)
    deployment.store.publishKeyPackages({
      version: 1, credential: charlie.credential,
      packages: [{ reference: new Uint8Array([12]), user: charlie.credential.user, client: charlie.credential.client, keyPackage: new Uint8Array([13]), publishedAt: at }], publishedAt: at, signature: new Uint8Array(),
    })

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
