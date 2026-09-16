import { describe, expect, test } from 'bun:test'
import { buildPlaintext } from '../../src/protocol/didcomm/message.ts'
import {
  GROUP_INVITE,
  GROUP_MESSAGE,
  didcommGroupAddress,
  groupInviteBodyOf,
  groupMessageBodyOf,
  groupRosterFromMessages,
  isGroupInvite,
  isGroupMessage,
  parseDidCommGroupAddress,
  randomDidCommGroupId,
} from '../../src/client/didcomm/group-chat.ts'

describe('DIDComm group invite message', () => {
  test('round-trips groupId/members/name through buildPlaintext', () => {
    const plaintext = buildPlaintext(GROUP_INVITE, { groupId: 'abc123', members: ['did:web:alice.example', 'did:web:bob.example'], name: 'Project Chat' })
    expect(isGroupInvite(plaintext)).toBe(true)
    expect(groupInviteBodyOf(plaintext)).toEqual({ groupId: 'abc123', members: ['did:web:alice.example', 'did:web:bob.example'], name: 'Project Chat' })
  })

  test('name is optional', () => {
    const plaintext = buildPlaintext(GROUP_INVITE, { groupId: 'abc123', members: ['did:web:alice.example'] })
    expect(groupInviteBodyOf(plaintext)).toEqual({ groupId: 'abc123', members: ['did:web:alice.example'] })
  })

  test('rejects a body missing groupId, with an empty member list, or with a non-string member', () => {
    expect(groupInviteBodyOf(buildPlaintext(GROUP_INVITE, { members: ['did:web:alice.example'] }))).toBeNull()
    expect(groupInviteBodyOf(buildPlaintext(GROUP_INVITE, { groupId: 'abc123', members: [] }))).toBeNull()
    expect(groupInviteBodyOf(buildPlaintext(GROUP_INVITE, { groupId: 'abc123' }))).toBeNull()
    expect(groupInviteBodyOf(buildPlaintext(GROUP_INVITE, { groupId: 'abc123', members: [1, 2] }))).toBeNull()
    expect(groupInviteBodyOf({ body: null })).toBeNull()
    expect(groupInviteBodyOf({ body: 'not an object' })).toBeNull()
  })

  test('a different message type is not recognized as an invite', () => {
    expect(isGroupInvite(buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'hi' }))).toBe(false)
  })
})

describe('DIDComm group message', () => {
  test('round-trips groupId/content/sentAt/subject through buildPlaintext', () => {
    const plaintext = buildPlaintext(GROUP_MESSAGE, { groupId: 'abc123', content: 'hello group', sentAt: '2026-09-02T00:00:00.000Z', subject: 'Hi' })
    expect(isGroupMessage(plaintext)).toBe(true)
    expect(groupMessageBodyOf(plaintext)).toEqual({ groupId: 'abc123', content: 'hello group', sentAt: '2026-09-02T00:00:00.000Z', subject: 'Hi' })
  })

  test('sentAt and subject are optional', () => {
    const plaintext = buildPlaintext(GROUP_MESSAGE, { groupId: 'abc123', content: 'hello group' })
    expect(groupMessageBodyOf(plaintext)).toEqual({ groupId: 'abc123', content: 'hello group' })
  })

  test('rejects a body missing groupId or content', () => {
    expect(groupMessageBodyOf(buildPlaintext(GROUP_MESSAGE, { content: 'hi' }))).toBeNull()
    expect(groupMessageBodyOf(buildPlaintext(GROUP_MESSAGE, { groupId: 'abc123' }))).toBeNull()
  })

  test('a different message type is not recognized as a group message', () => {
    expect(isGroupMessage(buildPlaintext(GROUP_INVITE, { groupId: 'abc123', members: ['did:web:alice.example'] }))).toBe(false)
  })
})

describe('DIDComm group address', () => {
  test('round-trips a groupId', () => {
    const groupId = randomDidCommGroupId()
    const address = didcommGroupAddress(groupId)
    expect(address).toBe(`didcomm-group:${groupId}`)
    expect(parseDidCommGroupAddress(address)).toBe(groupId)
  })

  test('rejects a non-group address', () => {
    expect(() => parseDidCommGroupAddress('mls:abc123')).toThrow()
    expect(() => parseDidCommGroupAddress('did:web:alice.example')).toThrow()
  })

  test('randomDidCommGroupId produces distinct 64-character hex ids', () => {
    const a = randomDidCommGroupId()
    const b = randomDidCommGroupId()
    expect(a).not.toBe(b)
    expect(a).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('DIDComm group roster recovery', () => {
  test('a second device reconstructs the complete roster from synced message metadata', () => {
    const groupId = 'group-from-vault'
    const threadId = didcommGroupAddress(groupId)
    const base = { mailboxIds: { inbox: true as const }, keywords: {}, receivedAt: '2026-09-16T00:00:00.000Z' }
    const emails = [
      { ...base, id: 'm1', threadId, from: [{ email: 'did:example:a' }], to: [{ email: 'did:example:b' }, { email: 'did:example:c' }], subject: 'Trio' },
      { ...base, id: 'm2', threadId, from: [{ email: 'did:example:b' }], to: [{ email: 'did:example:a' }, { email: 'did:example:c' }] },
      { ...base, id: 'other', threadId: 'didcomm-group:other', from: [{ email: 'did:example:mallory' }], to: [{ email: 'did:example:a' }] },
    ]

    expect(groupRosterFromMessages(groupId, 'did:example:a', emails)).toEqual({
      members: ['did:example:a', 'did:example:b', 'did:example:c'],
      name: 'Trio',
    })
  })

  test('does not invent a roster without a synced group message', () => {
    expect(groupRosterFromMessages('missing', 'did:example:a', [])).toBeNull()
  })
})
