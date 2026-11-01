// How a rotated DID reads when it is shown (PLAN-refactor.md §14.4, §14.5): the message is stored under the DID that
// authenticated it, and the contact cards -- whenever they arrive -- decide who that is for the person.
import { describe, expect, test } from 'vitest'
import { applyContactSet, didContactPatch, rotationPatch, rotatedEmail, rotationReader, type LocalJmapContactCard } from '../src/client/store/projection/contacts.ts'
import { didCommThreadId } from '../src/client/didcomm/basicmessage.ts'
import { groupConversation, didcommGroupAddress } from '../src/client/didcomm/group-chat.ts'
import { readRotated } from '../src/client/app/ui/rotation-view.ts'
import type { MailMessageView } from '../src/client/app/ui/message/message-view.ts'
import type { LocalJmapEmail } from '../src/client/store/projection/gateway.ts'
import { isReceiveOnlyDid, isReceiveOnlyThread, selfAddressesOf } from '../src/client/app/ui/thread-model.ts'
import { generatePeerIdentity } from '../src/protocol/didcomm/peer.ts'

const ME = 'did:vh:QmMe'
const BOB = 'did:vh:QmBob'
const Y1 = 'did:peer:2.Ez6LSy1.Vz6Mky1'
const Y2 = 'did:peer:2.Ez6LSy2.Vz6Mky2'
const AGENT = 'did:peer:2.Ez6LSagent.Vz6Mkagent'

function card(...rotations: Array<{ did: string; iat: number }>): LocalJmapContactCard {
  const creating = didContactPatch(BOB)
  let result = applyContactSet(undefined, creating)!
  for (const rotation of rotations) result = applyContactSet(result, rotationPatch(creating.cardId, { did: rotation.did, prior: BOB, iat: rotation.iat }))!
  return result
}

const view = (from: string, over: Partial<MailMessageView> = {}): MailMessageView => ({
  from, from_name: from, body: 'hi', subject: '', ts: 1, message_id: 'm', jmap_id: 'e', in_reply_to: '', thread_id: didCommThreadId(ME, from), to_addrs: [ME], ...over,
})

describe('rotationReader', () => {
  test('reads a rotated DID as its counterparty; anything else as it is', () => {
    const reader = rotationReader([card({ did: Y1, iat: 100 })])
    expect(reader.party(Y1)).toBe(BOB)
    expect(reader.party(BOB)).toBe(BOB)
    expect(reader.party(AGENT)).toBe(AGENT)
  })

  test('a counterparty\'s older DID is superseded once a newer one was recorded; the newest and unknown DIDs are not', () => {
    const reader = rotationReader([card({ did: Y1, iat: 100 }, { did: Y2, iat: 200 })])
    expect(reader.superseded(Y1)).toBe(true)
    expect(reader.superseded(Y2)).toBe(false)
    expect(reader.superseded(BOB)).toBe(false)
    expect(reader.superseded(AGENT)).toBe(false)
  })

  test('a 1:1 thread joins the counterparty\'s own once its card is known -- and is untouched before', () => {
    const stored = didCommThreadId(ME, Y1)
    expect(rotationReader([]).thread(stored)).toBe(stored)
    expect(rotationReader([card({ did: Y1, iat: 100 })]).thread(stored)).toBe(didCommThreadId(ME, BOB))
    // Group and notepad threads have no pair of keys to read.
    expect(rotationReader([card({ did: Y1, iat: 100 })]).thread(didcommGroupAddress('g1'))).toBe(didcommGroupAddress('g1'))
    expect(rotationReader([]).thread('notepad')).toBe('notepad')
  })
})

describe('readRotated (the screen)', () => {
  test('a message from a rotated DID is Bob\'s: sender, recipients and thread', () => {
    const reader = rotationReader([card({ did: Y1, iat: 100 })])
    expect(readRotated(view(Y1), reader)).toMatchObject({ from: BOB, thread_id: didCommThreadId(ME, BOB), to_addrs: [ME] })
    // What this identity wrote to the rotated DID reads as written to Bob.
    expect(readRotated(view(ME, { to_addrs: [Y1], thread_id: didCommThreadId(ME, Y1) }), reader)).toMatchObject({ from: ME, to_addrs: [BOB], thread_id: didCommThreadId(ME, BOB) })
  })

  test('the same messages read the same whether the card came first or last: only the row they are in changes', () => {
    const early = view(Y1, { jmap_id: 'e1' }); const late = view(BOB, { jmap_id: 'e2', thread_id: didCommThreadId(ME, BOB) })
    const without = rotationReader([])
    expect([readRotated(early, without)!.thread_id, readRotated(late, without)!.thread_id].sort().length).toBe(2)
    expect(new Set([early, late].map(m => readRotated(m, without)!.thread_id)).size).toBe(2) // two rows until the card is there
    const withCard = rotationReader([card({ did: Y1, iat: 100 })])
    expect(new Set([early, late].map(m => readRotated(m, withCard)!.thread_id)).size).toBe(1) // one conversation after
  })

  test('a DID with no card stays as it is, and a standalone did:peer is its own party', () => {
    expect(readRotated(view(AGENT), rotationReader([card({ did: Y1, iat: 100 })]))).toMatchObject({ from: AGENT, thread_id: didCommThreadId(ME, AGENT) })
  })

  test('a message from a DID its counterparty has left is not shown', () => {
    const reader = rotationReader([card({ did: Y1, iat: 100 }, { did: Y2, iat: 200 })])
    expect(readRotated(view(Y1), reader)).toBeNull()
    expect(readRotated(view(Y2), reader)).not.toBeNull()
  })

  test('the name made from the DID is made from the person\'s DID; a name the message came with stays', () => {
    const reader = rotationReader([card({ did: Y1, iat: 100 })])
    expect(readRotated(view(Y1, { from_name: Y1 }), reader)!.from_name).toBe(BOB)
    expect(readRotated(view(Y1, { from_name: 'Bob' }), reader)!.from_name).toBe('Bob')
  })
})

describe('rotatedEmail (the Markdown mirror) and group participants', () => {
  const email = (from: string, over: Partial<LocalJmapEmail> = {}): LocalJmapEmail => ({
    id: 'e', threadId: didCommThreadId(ME, from), mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-11-01T00:00:00Z', from: [{ email: from }], to: [{ email: ME }], ...over,
  })

  test('reads the sender, recipients and thread; drops what came from a DID that was left', () => {
    const reader = rotationReader([card({ did: Y1, iat: 100 }, { did: Y2, iat: 200 })])
    expect(rotatedEmail(email(Y2), reader)).toMatchObject({ from: [{ email: BOB }], threadId: didCommThreadId(ME, BOB) })
    expect(rotatedEmail(email(Y1), reader)).toBeNull()
  })

  test('a group\'s participants are the people, not the DIDs they sent from', () => {
    const thid = 'g1'
    const emails = [email(Y1, { threadId: didcommGroupAddress(thid), to: [{ email: ME }, { email: 'did:vh:QmCarol' }] })]
    expect(groupConversation(thid, emails)!.participants).toContain(Y1)
    expect(groupConversation(thid, emails, rotationReader([card({ did: Y1, iat: 100 })]))!.participants).toEqual([BOB, ME, 'did:vh:QmCarol'].sort())
  })
})

describe('a sender with nowhere to reply to (§14.6)', () => {
  const sendOnly = generatePeerIdentity().did
  const reachable = generatePeerIdentity({ uri: 'did:web:mediator.example' }).did
  const self = selfAddressesOf(undefined, ME)

  test('a did:peer:2 with no service is receive-only; with one, a public DID, or no DID at all, it is not', () => {
    expect(isReceiveOnlyDid(sendOnly)).toBe(true)
    expect(isReceiveOnlyDid(reachable)).toBe(false)
    expect(isReceiveOnlyDid(BOB)).toBe(false)
    expect(isReceiveOnlyDid('did:peer:2.not-a-did')).toBe(false)
    expect(isReceiveOnlyDid('alice@example.com')).toBe(false)
  })

  test('a thread is receive-only when everyone on the other side is', () => {
    expect(isReceiveOnlyThread([view(sendOnly)], self)).toBe(true)
    expect(isReceiveOnlyThread([view(reachable)], self)).toBe(false)
    expect(isReceiveOnlyThread([view(sendOnly), view(BOB)], self)).toBe(false)
    expect(isReceiveOnlyThread([], self)).toBe(false)
  })
})
