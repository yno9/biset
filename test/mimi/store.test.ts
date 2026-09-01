import { describe, expect, test } from 'bun:test'
import { Database } from 'bun:sqlite'
import { SqliteMimiStore } from '../../src/mimi/store.ts'
import { frankMessage, verifyFrank } from '../../src/mimi/franking.ts'
import { RoomPseudonymIssuer } from '../../src/mimi/anon/pseudonym.ts'
import type { UpdateRoomRequest, VisibleCredential } from '../../src/mimi/protocol-types.ts'

const at = '2026-09-01T00:00:00.000Z'
const roomId = 'mimi://example.test/r/store'
const alice: VisibleCredential = { kind: 'visible', user: 'did:web:alice', client: 'did:web:alice#phone', credential: new Uint8Array([1]), signaturePublicKey: new Uint8Array([2]) }
const bob: VisibleCredential = { kind: 'visible', user: 'did:web:bob', client: 'did:web:bob#laptop', credential: new Uint8Array([3]), signaturePublicKey: new Uint8Array([4]) }

function initialUpdate(): UpdateRoomRequest {
  return {
    version: 1, protocol: 'mls10', roomId, sender: alice, epoch: '0', bundle: { kind: 'commit', proposalOrCommit: new Uint8Array([10]) },
    initialState: {
      basePolicy: new Uint8Array(), participantList: { participants: [{ user: alice.user, roleIndex: 1, clientIds: [alice.client] }] },
      memberCredentials: [alice], metadata: { roomUri: roomId, roomName: 'Store' },
    },
    submittedAt: at, signature: new Uint8Array(),
  }
}

describe('MIMI SQLite store', () => {
  test('pseudonyms are stable within one room and unlinkable across rooms', () => {
    const issuer = new RoomPseudonymIssuer('mimi.example.test')
    expect(issuer.userPseudonym('room-a', alice.user)).toBe(issuer.userPseudonym('room-a', alice.user))
    expect(issuer.userPseudonym('room-a', alice.user)).not.toBe(issuer.userPseudonym('room-b', alice.user))
    expect(issuer.clientPseudonym('room-a', alice.client)).toMatch(/^mimi:\/\/mimi\.example\.test\/u\/[0-9a-f-]{36}$/)
  })

  test('serializes room commits, records deliveries, and atomically consumes compatible KeyPackages', () => {
    const store = new SqliteMimiStore(new Database(':memory:'))
    const created = store.submitUpdate(initialUpdate())
    expect(created.ok).toBe(true)
    if (!created.ok) throw new Error('unreachable')
    expect(created.state.epoch).toBe('1')

    const added = store.submitUpdate({
      version: 1, protocol: 'mls10', roomId, sender: alice, epoch: '1', bundle: { kind: 'commit', proposalOrCommit: new Uint8Array([11]), welcome: new Uint8Array([12]) },
      stateUpdate: {
        participantList: { participants: [{ user: alice.user, roleIndex: 1 }, { user: bob.user, roleIndex: 1, clientIds: [bob.client] }] },
        memberCredentials: [alice, bob],
      }, submittedAt: at, signature: new Uint8Array(),
    })
    expect(added.ok).toBe(true)
    expect(store.deliveriesSince(roomId, bob.user, 0)?.map(entry => entry.kind)).toEqual(['commit', 'welcome', 'commit'])

    const stale = store.submitUpdate({ version: 1, protocol: 'mls10', roomId, sender: alice, epoch: '1', bundle: { kind: 'proposal', proposalOrCommit: new Uint8Array([13]) }, submittedAt: at, signature: new Uint8Array() })
    expect(stale).toMatchObject({ ok: false, reason: 'wrongEpoch', currentEpoch: '2' })

    store.publishKeyPackages({
      version: 1, credential: bob,
      packages: [
        { reference: new Uint8Array([20]), user: bob.user, client: bob.client, keyPackage: new Uint8Array([21]), capabilities: { extensions: [7] }, publishedAt: at },
        { reference: new Uint8Array([22]), user: bob.user, client: bob.client, keyPackage: new Uint8Array([23]), capabilities: { extensions: [8] }, publishedAt: at },
      ], publishedAt: at, signature: new Uint8Array(),
    })
    expect(store.takeKeyPackages(bob.user, { extensions: [7] }).map(item => item.keyPackage)).toEqual([new Uint8Array([21])])
    expect(store.keyPackageCount(bob.user)).toBe(1)
    store.close()
  })

  test('creates stable room-local franking keys and produces verifiable context-bound evidence', () => {
    const store = new SqliteMimiStore(new Database(':memory:'))
    expect(store.submitUpdate(initialUpdate()).ok).toBe(true)
    const keys = store.frankingKeys(roomId)
    expect(keys).toBeDefined()
    if (!keys) throw new Error('unreachable')
    expect(store.frankingKeys(roomId)).toEqual(keys)
    const frank = frankMessage(keys, { aad: { frankingTag: new Uint8Array(32).fill(9) }, senderUri: alice.user, roomUri: roomId, acceptedTimestamp: '1', ciphersuite: 1 })
    expect(verifyFrank(keys.signingPublicKey, frank)).toBe(true)
    expect(verifyFrank(keys.signingPublicKey, { ...frank, context: { ...frank.context, senderUri: 'did:web:mallory' } })).toBe(false)
    store.close()
  })
})
