import { describe, expect, test } from 'bun:test'
import { buildPlaintext } from '../../src/didcomm/message.ts'
import {
  CONVERSATION_GROUP_INVITE,
  conversationGroupInviteBodyOf,
  isConversationGroupInvite,
} from '../../src/mls/conversation-group-invite.ts'

describe('Conversation Group invite message', () => {
  test('round-trips groupId/ds/groupName through buildPlaintext', () => {
    const plaintext = buildPlaintext(CONVERSATION_GROUP_INVITE, { groupId: 'abc123', ds: 'did:web:alice.example', groupName: 'Project Chat' })
    expect(isConversationGroupInvite(plaintext)).toBe(true)
    expect(conversationGroupInviteBodyOf(plaintext)).toEqual({ groupId: 'abc123', ds: 'did:web:alice.example', groupName: 'Project Chat' })
  })

  test('groupName is optional', () => {
    const plaintext = buildPlaintext(CONVERSATION_GROUP_INVITE, { groupId: 'abc123', ds: 'did:web:alice.example' })
    expect(conversationGroupInviteBodyOf(plaintext)).toEqual({ groupId: 'abc123', ds: 'did:web:alice.example' })
  })

  test('rejects a body missing groupId or ds', () => {
    expect(conversationGroupInviteBodyOf(buildPlaintext(CONVERSATION_GROUP_INVITE, { ds: 'did:web:alice.example' }))).toBeNull()
    expect(conversationGroupInviteBodyOf(buildPlaintext(CONVERSATION_GROUP_INVITE, { groupId: 'abc123' }))).toBeNull()
    expect(conversationGroupInviteBodyOf({ body: null })).toBeNull()
    expect(conversationGroupInviteBodyOf({ body: 'not an object' })).toBeNull()
  })

  test('a different message type is not recognized as an invite', () => {
    expect(isConversationGroupInvite(buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'hi' }))).toBe(false)
  })
})
