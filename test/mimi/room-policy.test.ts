import { describe, expect, test } from 'bun:test'
import { authorizeParticipantListTransition, maySendMessage, validateRoomPolicy, type MimiRoomPolicy } from '../../src/server/mimi/room-policy.ts'

const policy: MimiRoomPolicy = {
  roles: [
    { roleIndex: 0, capabilities: [], minimumParticipants: 0, minimumActiveParticipants: 0, authorizedRoleChanges: [] },
    { roleIndex: 2, capabilities: ['canAddParticipant', 'canRemoveParticipant', 'canRemoveSelf', 'canSendMessage'], minimumParticipants: 0, maximumParticipants: 2, minimumActiveParticipants: 0, authorizedRoleChanges: [{ fromRoleIndex: 2, targetRoleIndexes: [0] }, { fromRoleIndex: 0, targetRoleIndexes: [2] }] },
    { roleIndex: 3, capabilities: ['canChangeUserRole'], minimumParticipants: 0, minimumActiveParticipants: 0, authorizedRoleChanges: [{ fromRoleIndex: 2, targetRoleIndexes: [3] }] },
  ],
}

const alice = { user: 'did:web:alice', roleIndex: 2, clientIds: ['did:web:alice#phone'] }
const bob = { user: 'did:web:bob', roleIndex: 2, clientIds: ['did:web:bob#laptop'] }

describe('MIMI room policy evaluator', () => {
  test('validates role definitions and the reserved absent-participant role', () => {
    expect(() => validateRoomPolicy(policy)).not.toThrow()
    expect(() => validateRoomPolicy({ roles: policy.roles.slice(1) })).toThrow('reserved role index zero')
    expect(() => validateRoomPolicy({ roles: [{ ...policy.roles[0]!, roleIndex: 2 }, policy.roles[1]!] })).toThrow('duplicate role indexes')
    expect(() => validateRoomPolicy({ roles: [{ ...policy.roles[0]!, authorizedRoleChanges: [{ fromRoleIndex: 0, targetRoleIndexes: [99] }] }, ...policy.roles.slice(1)] })).toThrow('undefined role')
  })

  test('authorizes explicit permitted add/remove transitions and enforces maximum counts', () => {
    const current = { participants: [alice] }
    const added = { participants: [alice, bob] }
    expect(authorizeParticipantListTransition(policy, current, added, alice.user)).toEqual({ allowed: true })
    expect(authorizeParticipantListTransition(policy, added, { participants: [alice] }, alice.user)).toEqual({ allowed: true })
    expect(authorizeParticipantListTransition(policy, added, { participants: [alice, bob, { user: 'did:web:charlie', roleIndex: 2 }] }, alice.user)).toMatchObject({ allowed: false, reason: expect.stringContaining('participant count') })
  })

  test('rejects ungranted or inconsistent transitions and exposes hub-enforceable send permission', () => {
    const current = { participants: [alice, bob] }
    expect(authorizeParticipantListTransition(policy, current, { participants: [alice, { ...bob, roleIndex: 3 }] }, alice.user)).toMatchObject({ allowed: false })
    expect(authorizeParticipantListTransition(policy, current, { participants: [bob] }, bob.user)).toEqual({ allowed: true })
    expect(maySendMessage(policy, current, alice.user)).toBe(true)
    expect(maySendMessage(policy, { participants: [{ ...alice, roleIndex: 3 }] }, alice.user)).toBe(false)
  })
})
