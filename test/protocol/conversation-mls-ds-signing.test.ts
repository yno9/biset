import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { mlsGroupCreationSigningBytes } from '../../src/protocol/signing.ts'
import {
  conversationCommitSubmitSigningBytes,
  conversationGroupCreateSigningBytes,
  conversationKeyPackageTakeSigningBytes,
  conversationMessageSubmitSigningBytes,
} from '../../src/protocol/conversation-mls-ds-signing.ts'

describe('Conversation Group DS signing bytes (identity-blind: group-local ids, no deviceCredential/roster snapshot)', () => {
  test('binds group-create to groupId/creatorId/createdAt', () => {
    const value = { version: 1 as const, groupId: 'group-1', creatorId: 'aa', createdAt: '2026-08-31T00:00:00.000Z' }
    expect(conversationGroupCreateSigningBytes(value)).toEqual(conversationGroupCreateSigningBytes({ ...value }))
    expect(equalBytes(conversationGroupCreateSigningBytes(value), conversationGroupCreateSigningBytes({ ...value, groupId: 'group-2' }))).toBe(false)
    expect(equalBytes(conversationGroupCreateSigningBytes(value), conversationGroupCreateSigningBytes({ ...value, creatorId: 'bb' }))).toBe(false)
  })

  test('binds commit-submit to the exact commit/epoch/welcome/addedIds/removedIds', () => {
    const value = {
      version: 1 as const, groupId: 'group-1', senderId: 'aa', epoch: '4',
      commit: new Uint8Array([1, 2, 3]), submittedAt: '2026-08-31T00:01:00.000Z',
    }
    expect(equalBytes(conversationCommitSubmitSigningBytes(value), conversationCommitSubmitSigningBytes({ ...value, epoch: '5' }))).toBe(false)
    expect(equalBytes(conversationCommitSubmitSigningBytes(value), conversationCommitSubmitSigningBytes({ ...value, commit: new Uint8Array([9]) }))).toBe(false)
    expect(equalBytes(
      conversationCommitSubmitSigningBytes(value),
      conversationCommitSubmitSigningBytes({ ...value, welcome: new Uint8Array([1]), addedIds: ['bb'] }),
    )).toBe(false)
    expect(equalBytes(
      conversationCommitSubmitSigningBytes({ ...value, addedIds: ['bb'] }),
      conversationCommitSubmitSigningBytes({ ...value, removedIds: ['bb'] }),
    )).toBe(false)
  })

  test('keypackage-take is targeted (targetId), unlike Self Group\'s requester-only version', () => {
    const value = { version: 1 as const, requesterId: 'aa', targetId: 'bb', requestedAt: '2026-08-31T00:02:00.000Z' }
    expect(equalBytes(conversationKeyPackageTakeSigningBytes(value), conversationKeyPackageTakeSigningBytes({ ...value, targetId: 'cc' }))).toBe(false)
  })

  test('binds message-submit (the Self Group DS has no equivalent of) to the exact privateMessage bytes and epoch', () => {
    const value = { version: 1 as const, groupId: 'group-1', senderId: 'aa', epoch: '5', privateMessage: new Uint8Array([1, 2, 3]), submittedAt: '2026-08-31T00:03:00.000Z' }
    expect(equalBytes(conversationMessageSubmitSigningBytes(value), conversationMessageSubmitSigningBytes({ ...value, privateMessage: new Uint8Array([9]) }))).toBe(false)
    expect(equalBytes(conversationMessageSubmitSigningBytes(value), conversationMessageSubmitSigningBytes({ ...value, epoch: '6' }))).toBe(false)
  })

  test('a Conversation Group group-create never collides with a Self Group one signing similar fields (distinct label namespaces)', () => {
    const conversation = conversationGroupCreateSigningBytes({ version: 1, groupId: 'group-1', creatorId: 'aa', createdAt: '2026-08-31T00:00:00.000Z' })
    const selfGroup = mlsGroupCreationSigningBytes({ version: 1, groupId: 'group-1', identityId: 'did:web:alice.example', creatorKid: 'did:web:alice.example#key-1', roster: ['did:web:alice.example#key-1'], createdAt: '2026-08-31T00:00:00.000Z' })
    expect(equalBytes(conversation, selfGroup)).toBe(false)
  })
})
