// A DIDComm group chat is its own inbox. Found live 2026-10-03: a 1:1 chat
// and a group chat from the same person landed in ONE inbox row (as two
// threads), because both are keyed on who the messages came from.
import { describe, expect, test } from 'bun:test'
import { DIDCOMM_GROUP_THREAD_PREFIX, groupMessages, inboxKeyForThread, processedMessages } from '../src/client/app/ui/message/message-view.ts'

describe('inboxKeyForThread', () => {
  const c8de = 'did:webvh:QmUKjahfVxnJHfj9iiWurMh6XF4umMdNvnqASv1LdAsNme:c8de.did.md'

  test('a 1:1 chat belongs to the inbox of whoever it is with', () => {
    expect(inboxKeyForThread('thread-1', c8de)).toBe(c8de)
    expect(inboxKeyForThread(undefined, c8de)).toBe(c8de)
  })

  test('a group chat is its own inbox, even though its messages come from the same person as the 1:1 chat', () => {
    const group = `${DIDCOMM_GROUP_THREAD_PREFIX}7d2e9a`
    expect(inboxKeyForThread(group, c8de)).toBe(group)
    expect(inboxKeyForThread(group, c8de)).not.toBe(inboxKeyForThread('thread-1', c8de))
  })

  test('two groups with the same person are two inboxes', () => {
    expect(inboxKeyForThread(`${DIDCOMM_GROUP_THREAD_PREFIX}a`, c8de)).not.toBe(inboxKeyForThread(`${DIDCOMM_GROUP_THREAD_PREFIX}b`, c8de))
  })
})

describe('a thread\'s title', () => {
  const message = (ts: number, subject: string, threadId: string) => ({
    bodyText: '',
    msg: { from: 'did:webvh:abc:c8de.did.md', from_name: 'c8de', body: '', subject, ts, message_id: `m${ts}`, jmap_id: `j${ts}`, in_reply_to: '', thread_id: threadId },
  })

  test('is the earliest message that has a subject, whatever order this device loaded them in; none when no message has one', () => {
    processedMessages.length = 0
    // Loaded newest first, as a second device may receive them.
    processedMessages.push(message(3, 'later title', 'didcomm-group:g1'), message(1, 'first title', 'didcomm-group:g1'), message(2, '', 'didcomm-group:g1'))
    processedMessages.push(message(5, '', 'didcomm-group:g2'))
    const groups = groupMessages()
    expect(groups.find(g => g.messages[0]!.msg.thread_id === 'didcomm-group:g1')!.subject).toBe('first title')
    expect(groups.find(g => g.messages[0]!.msg.thread_id === 'didcomm-group:g2')!.subject).toBe('')
    processedMessages.length = 0
  })
})
