import { describe, expect, test } from 'bun:test'
import { createMimiDeployment } from '../../src/mimi/deployment.ts'
import { MimiFanoutDispatcher } from '../../src/mimi/fanout.ts'
import { MimiProviderTransport } from '../../src/mimi/provider-transport.ts'
import type { UpdateRoomRequest, VisibleCredential } from '../../src/mimi/protocol-types.ts'
import type { MimiMlsStateTransition } from '../../src/mimi/mls-appsync.ts'

const roomId = 'mimi://hub.example/r/shared'
const at = '2026-09-01T00:00:00.000Z'
const member: VisibleCredential = { kind: 'visible', user: 'did:web:member', client: 'did:web:member#device', credential: new Uint8Array([1]), signaturePublicKey: new Uint8Array(32).fill(2) }

function initial(): UpdateRoomRequest { return { version: 1, protocol: 'mls10', roomId, sender: member, epoch: '0', bundle: { kind: 'commit', proposalOrCommit: new Uint8Array([1]) }, initialState: { basePolicy: new Uint8Array(), participantList: { participants: [{ user: member.user, roleIndex: 1, clientIds: [member.client] }] }, memberCredentials: [member], metadata: { roomUri: roomId, roomName: 'shared' } }, submittedAt: at, signature: new Uint8Array() } }

function initialTransition(frankingSignatureKey: Uint8Array): MimiMlsStateTransition {
  return { participantListUpdates: [{ changedRoleParticipants: [], removedIndices: [], addedParticipants: [{ user: member.user, roleIndex: 1 }] }], roomMetadata: { roomUri: roomId, roomName: 'shared' }, frankingAgent: { frankingSignatureKey, credential: new Uint8Array() } }
}

describe('MIMI Phase 3 federation release gate', () => {
  test('a hub commit reaches a separate follower through mTLS-bound notify and local delivery', async () => {
    const hub = createMimiDeployment({ databasePath: ':memory:', mode: 'normal' })
    const follower = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', federation: { providerDomain: 'follower.example', authenticatePeer: async () => ({ providerDomain: 'hub.example' }) } })
    expect(hub.store.submitUpdate(initial(), initialTransition(hub.store.prepareFrankingKeys(roomId).signingPublicKey)).ok).toBe(true)
    expect(follower.store.submitUpdate(initial(), initialTransition(follower.store.prepareFrankingKeys(roomId).signingPublicKey)).ok).toBe(true)
    const update = { version: 1, protocol: 'mls10' as const, roomId, sender: member, epoch: '1', bundle: { kind: 'commit' as const, proposalOrCommit: new Uint8Array([9]) }, submittedAt: at, signature: new Uint8Array() }
    const accepted = hub.store.submitUpdate(update)
    if (!accepted.ok) throw new Error('hub update failed')
    const transport = new MimiProviderTransport({ sourceProviderDomain: 'hub.example', tls: { cert: 'cert', key: 'key' }, fetchImpl: async (input, init) => { const { tls: _tls, ...requestInit } = init ?? {}; return follower.fetch(new Request(input, requestInit)) } })
    await new MimiFanoutDispatcher(transport).send({ providerBaseUrl: 'https://follower.example', roomId }, { timestamp: '1770000000000', entries: accepted.entries })
    expect(follower.store.deliveriesSince(roomId, member.user, 0)?.some(entry => entry.payload[0] === 9)).toBe(true)
    hub.close(); follower.close()
  })
})
