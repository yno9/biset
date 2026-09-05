import { describe, expect, test } from 'bun:test'
import { Database } from 'bun:sqlite'
import { SqliteMimiStore } from '../../src/server/mimi/store.ts'
import { frankMessage, verifyFrank } from '../../src/server/mimi/franking.ts'
import { RoomPseudonymIssuer } from '../../src/server/mimi/anon/pseudonym.ts'
import { decryptIdentityLink, encryptIdentityLink } from '../../src/server/mimi/anon/identity-link.ts'
import type { UpdateRoomRequest, VisibleCredential } from '../../src/server/mimi/protocol-types.ts'
import type { MimiMlsStateTransition } from '../../src/server/mimi/mls-appsync.ts'
import { createMlsGroup, encryptApplication, generateOwnKeyPackageForCredential } from '../../src/mls/group.ts'

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

function createInitial(store: SqliteMimiStore) {
  const frankingSignatureKey = store.prepareFrankingKeys(roomId).signingPublicKey
  const transition: MimiMlsStateTransition = {
    participantListUpdates: [{ changedRoleParticipants: [], removedIndices: [], addedParticipants: [{ user: alice.user, roleIndex: 1 }] }],
    roomMetadata: { roomUri: roomId, roomName: 'Store' }, frankingAgent: { frankingSignatureKey, credential: new Uint8Array() },
  }
  return store.submitUpdate(initialUpdate(), transition)
}

describe('MIMI SQLite store', () => {
  test('pseudonyms are stable within one room and unlinkable across rooms', () => {
    const issuer = new RoomPseudonymIssuer('mimi.example.test')
    expect(issuer.userPseudonym('room-a', alice.user)).toBe(issuer.userPseudonym('room-a', alice.user))
    expect(issuer.userPseudonym('room-a', alice.user)).not.toBe(issuer.userPseudonym('room-b', alice.user))
    expect(issuer.clientPseudonym('room-a', alice.client)).toMatch(/^mimi:\/\/mimi\.example\.test\/u\/[0-9a-f-]{36}$/)
  })

  test('pins each persisted database to one deployment mode and rejects visible state in anon mode', () => {
    const database = new Database(':memory:')
    const normal = new SqliteMimiStore(database, 'normal')
    expect(() => new SqliteMimiStore(database, 'anon')).toThrow('belongs to normal-mode')
    normal.close()

    const anon = new SqliteMimiStore(new Database(':memory:'), 'anon')
    expect(() => anon.submitUpdate(initialUpdate())).toThrow('anon-mode database rejects visible credentials')
    anon.close()
  })

  test('identity links are client-side epoch-exporter ciphertexts, not hub keys', async () => {
    const exporter = { async exportSecret(_label: string, context: Uint8Array) { return new Uint8Array(32).fill(context[context.length - 1]!) } }
    const ciphertext = await encryptIdentityLink(exporter, roomId, new Uint8Array([1, 2, 3]))
    expect(ciphertext).not.toEqual(new Uint8Array([1, 2, 3]))
    expect(await decryptIdentityLink(exporter, roomId, ciphertext)).toEqual(new Uint8Array([1, 2, 3]))
    await expect(decryptIdentityLink({ async exportSecret() { return new Uint8Array(32).fill(9) } }, roomId, ciphertext)).rejects.toThrow()
  })

  test('a joining member decrypts every current identity link, while a discarded epoch key cannot open the next epoch', async () => {
    const epochOne = { async exportSecret() { return new Uint8Array(32).fill(1) } }
    const epochTwo = { async exportSecret() { return new Uint8Array(32).fill(2) } }
    const encoder = new TextEncoder()
    const decoder = new TextDecoder()
    const links = await Promise.all(['did:web:alice', 'did:web:bob'].map(identity => encryptIdentityLink(epochOne, roomId, encoder.encode(identity))))
    expect(await Promise.all(links.map(link => decryptIdentityLink(epochOne, roomId, link).then(decoder.decode.bind(decoder))))).toEqual(['did:web:alice', 'did:web:bob'])
    const reencrypted = await encryptIdentityLink(epochTwo, roomId, encoder.encode('did:web:alice'))
    await expect(decryptIdentityLink(epochOne, roomId, reencrypted)).rejects.toThrow()
    expect(decoder.decode(await decryptIdentityLink(epochTwo, roomId, reencrypted))).toBe('did:web:alice')
  })

  test('serializes room commits, records deliveries, and atomically consumes compatible KeyPackages', () => {
    const store = new SqliteMimiStore(new Database(':memory:'))
    const created = createInitial(store)
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
    expect(createInitial(store).ok).toBe(true)
    const keys = store.frankingKeys(roomId)
    expect(keys).toBeDefined()
    if (!keys) throw new Error('unreachable')
    expect(store.frankingKeys(roomId)).toEqual(keys)
    const frank = frankMessage(keys, { aad: { frankingTag: new Uint8Array(32).fill(9) }, senderUri: alice.user, roomUri: roomId, acceptedTimestamp: '1', ciphersuite: 1 })
    expect(verifyFrank(keys.signingPublicKey, frank)).toBe(true)
    expect(verifyFrank(keys.signingPublicKey, { ...frank, context: { ...frank.context, senderUri: 'did:web:mallory' } })).toBe(false)
    store.close()
  })

  test('accepts a monotonic Vault checkpoint manifest and compacts only covered application payloads', () => {
    const store = new SqliteMimiStore(new Database(':memory:'))
    expect(createInitial(store).ok).toBe(true)
    const keys = store.frankingKeys(roomId)!
    const submit = (payload: Uint8Array) => store.submitMessage(roomId, alice.user, '1', payload, frankMessage(keys, { aad: { frankingTag: new Uint8Array(32).fill(1) }, senderUri: alice.user, roomUri: roomId, acceptedTimestamp: '1', ciphersuite: 1 }), at)
    expect(submit(new Uint8Array([10])).ok).toBe(true)
    expect(submit(new Uint8Array([11])).ok).toBe(true)
    const manifest = { coveredSeq: 2, transferId: 'A'.repeat(24), chunkCount: 2, payloadHash: new Uint8Array(32).fill(7) }
    const checkpoint = store.submitVaultCheckpoint({ version: 1, protocol: 'mls10', roomId, sender: alice, epoch: '1', manifest, submittedAt: at, signature: new Uint8Array() })
    expect(checkpoint).toMatchObject({ ok: true, entry: { kind: 'vaultCheckpoint', vaultCheckpoint: manifest } })
    const entries = store.deliveriesSince(roomId, alice.user, 0)!
    expect(entries.find(entry => entry.seq === 2)?.payload).toEqual(new Uint8Array())
    expect(entries.find(entry => entry.seq === 3)?.payload).toEqual(new Uint8Array([11]))
    expect(entries.at(-1)).toMatchObject({ kind: 'vaultCheckpoint', vaultCheckpoint: manifest })
    expect(store.submitVaultCheckpoint({ version: 1, protocol: 'mls10', roomId, sender: alice, epoch: '1', manifest, submittedAt: at, signature: new Uint8Array() })).toMatchObject({ ok: true, entry: { seq: checkpoint.ok ? checkpoint.entry.seq : -1 } })
    expect(store.submitVaultCheckpoint({ version: 1, protocol: 'mls10', roomId, sender: alice, epoch: '1', manifest: { ...manifest, payloadHash: new Uint8Array(32).fill(8) }, submittedAt: at, signature: new Uint8Array() })).toMatchObject({ ok: false, reason: 'conflict' })
    store.close()
  })

  test('deduplicates a Vault deliveryId but rejects rebinding it to another payload', () => {
    const store = new SqliteMimiStore(new Database(':memory:')); expect(createInitial(store).ok).toBe(true)
    const keys = store.frankingKeys(roomId)!, frank = frankMessage(keys, { aad: { frankingTag: new Uint8Array(32).fill(2) }, senderUri: alice.user, roomUri: roomId, acceptedTimestamp: '1', ciphersuite: 1 })
    const first = store.submitMessage(roomId, alice.user, '1', new Uint8Array([1]), frank, at, 'C'.repeat(24))
    const retry = store.submitMessage(roomId, alice.user, '1', new Uint8Array([1]), frank, '2026-09-02T00:00:00.000Z', 'C'.repeat(24))
    expect(retry).toMatchObject({ ok: true, entry: { seq: first.ok ? first.entry.seq : -1, acceptedAt: at } })
    expect(() => store.submitMessage(roomId, alice.user, '1', new Uint8Array([2]), frank, at, 'C'.repeat(24))).toThrow('deliveryId is bound')
    store.close()
  })

  test('stores an MLS-encrypted Vault payload without exposing its event metadata', async () => {
    const store = new SqliteMimiStore(new Database(':memory:')); expect(createInitial(store).ok).toBe(true)
    const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(alice.client) })
    const group = await createMlsGroup(new TextEncoder().encode(roomId), own)
    const plaintext = new TextEncoder().encode('{"kind":"message.add","targetIds":["private-target"]}')
    const encrypted = await encryptApplication(group, plaintext)
    expect(new TextDecoder().decode(encrypted.wire)).not.toContain('message.add')
    const keys = store.frankingKeys(roomId)!, frank = frankMessage(keys, { aad: { frankingTag: new Uint8Array(32).fill(3) }, senderUri: alice.user, roomUri: roomId, acceptedTimestamp: '1', ciphersuite: 1 })
    expect(store.submitMessage(roomId, alice.user, '1', encrypted.wire, frank, at, 'D'.repeat(24)).ok).toBe(true)
    expect(new TextDecoder().decode(store.deliveriesSince(roomId, alice.user, 0)!.at(-1)!.payload)).not.toContain('private-target')
    store.close()
  })

  test('accepts a provider fanout exactly once and exposes it through local delivery', () => {
    const store = new SqliteMimiStore(new Database(':memory:'))
    expect(createInitial(store).ok).toBe(true)
    const entries = [{ seq: 99, kind: 'proposal' as const, payload: new Uint8Array([42]), epoch: '1', acceptedAt: at }]
    expect(store.acceptProviderFanout(roomId, 'hub.example', 'body-hash', entries)).toBe('accepted')
    expect(store.acceptProviderFanout(roomId, 'hub.example', 'body-hash', entries)).toBe('duplicate')
    expect(store.deliveriesSince(roomId, alice.user, 0)?.map(entry => entry.payload)).toContainEqual(new Uint8Array([42]))
    store.close()
  })
})
