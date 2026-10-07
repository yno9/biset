// Group chat is a thread of Basic Messages addressed to more than one party
// (PLAN-refactor.md §8): `to` names the participants, `thid` the conversation,
// and the participants of a group are those of its latest message.
import { describe, expect, test } from 'bun:test'
import {
  didcommGroupAddress,
  groupConversation,
  isGroupAudience,
  parseDidCommGroupAddress,
} from '../../src/client/didcomm/group-chat.ts'
import type { LocalJmapEmail } from '../../src/client/store/projection/gateway.ts'

const ALICE = 'did:webvh:QmA:alice.example'
const BOB = 'did:webvh:QmB:bob.example'
const CAROL = 'did:webvh:QmC:carol.example'
const DAVE = 'did:webvh:QmD:dave.example'

const email = (id: string, sentAt: string, from: string, to: string[], extra: Partial<LocalJmapEmail> = {}): LocalJmapEmail => ({
  id, threadId: didcommGroupAddress('g1'), mailboxIds: { inbox: true }, keywords: {}, receivedAt: sentAt, sentAt,
  from: [{ email: from }], to: to.map(value => ({ email: value })), ...extra,
})

describe('the group thread address', () => {
  test('round-trips a thid', () => {
    expect(parseDidCommGroupAddress(didcommGroupAddress('thread-1'))).toBe('thread-1')
  })
  test('rejects anything else', () => {
    expect(() => parseDidCommGroupAddress('mls:abc')).toThrow('not a DIDComm group address')
  })
})

describe('isGroupAudience', () => {
  test('more than one recipient is a group; one, or none (read as Bcc), is not', () => {
    expect(isGroupAudience([BOB, CAROL])).toBe(true)
    expect(isGroupAudience([BOB])).toBe(false)
    expect(isGroupAudience([])).toBe(false)
    expect(isGroupAudience(undefined)).toBe(false)
  })
})

describe('groupConversation', () => {
  test('its participants are the sender and recipients of its latest message', () => {
    const emails = [
      email('m1', '2026-10-07T00:00:00.000Z', ALICE, [BOB, CAROL]),
      email('m2', '2026-10-07T00:01:00.000Z', BOB, [ALICE, CAROL, DAVE]),
    ]
    expect(groupConversation('g1', emails)?.participants).toEqual([ALICE, BOB, CAROL, DAVE].sort())
  })

  test('someone dropped by the latest message stays dropped, even if an older message named them', () => {
    const emails = [
      email('m2', '2026-10-07T00:01:00.000Z', ALICE, [BOB, CAROL]),
      email('m1', '2026-10-07T00:00:00.000Z', ALICE, [BOB, CAROL, DAVE]),
    ]
    expect(groupConversation('g1', emails)?.participants).toEqual([ALICE, BOB, CAROL].sort())
  })

  test('its name is the latest subject given', () => {
    const emails = [
      email('m1', '2026-10-07T00:00:00.000Z', ALICE, [BOB, CAROL], { subject: 'Old name' }),
      email('m2', '2026-10-07T00:01:00.000Z', BOB, [ALICE, CAROL], { subject: 'New name' }),
      email('m3', '2026-10-07T00:02:00.000Z', CAROL, [ALICE, BOB]),
    ]
    expect(groupConversation('g1', emails)?.name).toBe('New name')
  })

  test('another conversation, or none, is not this one', () => {
    expect(groupConversation('g1', [email('m1', '2026-10-07T00:00:00.000Z', ALICE, [BOB, CAROL], { threadId: didcommGroupAddress('g2') })])).toBeNull()
    expect(groupConversation('g1', [])).toBeNull()
  })
})
