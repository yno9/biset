import { describe, expect, test } from 'bun:test'
import { computeReplyContext } from '../src/client/app/mail/message-view.ts'
import type { ProcessedMessage } from '../src/client/app/mail/message-view.ts'

function msg(overrides: Partial<ProcessedMessage['msg']>): ProcessedMessage {
  return {
    msg: {
      from: '', from_name: '', body: '', subject: '', ts: 0, message_id: '', jmap_id: '',
      in_reply_to: '', thread_id: 't', to_addrs: [], ...overrides,
    },
    bodyText: '',
  }
}

describe('computeReplyContext', () => {
  test('dedupes participants and excludes the caller\'s own address', () => {
    const thread = [
      msg({ from: 'alice@x.test', to_addrs: ['me@x.test'], message_id: 'm1', ts: 1 }),
      msg({ from: 'me@x.test', to_addrs: ['alice@x.test'], message_id: 'm2', ts: 2 }),
      msg({ from: 'alice@x.test', to_addrs: ['me@x.test', 'bob@x.test'], message_id: 'm3', ts: 3 }),
    ]
    const { toAddrs } = computeReplyContext(thread, 'me@x.test')
    expect(toAddrs).toEqual(['alice@x.test', 'bob@x.test'])
  })

  test('address comparison is case-insensitive', () => {
    const thread = [msg({ from: 'Alice@X.test', to_addrs: ['ME@x.test'], message_id: 'm1', ts: 1 })]
    const { toAddrs } = computeReplyContext(thread, 'me@x.test')
    expect(toAddrs).toEqual(['Alice@X.test'])
  })

  test('references is the oldest -> newest message-id chain, regardless of input order', () => {
    const thread = [
      msg({ from: 'a@x.test', message_id: 'm3', ts: 3 }),
      msg({ from: 'a@x.test', message_id: 'm1', ts: 1 }),
      msg({ from: 'a@x.test', message_id: 'm2', ts: 2 }),
    ]
    const { references } = computeReplyContext(thread, 'me@x.test')
    expect(references).toEqual(['m1', 'm2', 'm3'])
  })

  test('an empty thread yields empty results', () => {
    expect(computeReplyContext([], 'me@x.test')).toEqual({ toAddrs: [], references: [] })
  })

  // Found live 2026-08-25: a DIDComm thread's messages carry DIDs, not mail
  // addresses, in from/to_addrs -- filtering against only the mail address
  // (thread.ts's old single-string call) left this identity's OWN did
  // unrecognized as "self", so it ended up in toAddrs alongside the real
  // recipient. That made toAddrs.length 2 instead of 1, which failed
  // main.ts's `toAddrs.length === 1 && toAddrs[0].startsWith('did:')`
  // DIDComm check and silently fell through to a mail submission addressed
  // to a DID string (the core rejected it: "invalid recipient address").
  test('multiple self-identifiers: excludes both this identity\'s mail address and its own DID', () => {
    const thread = [
      msg({ from: 'did:webvh:abc:me.biset.md', to_addrs: ['did:webvh:xyz:them.biset.md'], message_id: 'm1', ts: 1 }),
      msg({ from: 'did:webvh:xyz:them.biset.md', to_addrs: ['did:webvh:abc:me.biset.md'], message_id: 'm2', ts: 2 }),
    ]
    const { toAddrs } = computeReplyContext(thread, ['me@mail.biset.md', 'did:webvh:abc:me.biset.md'])
    expect(toAddrs).toEqual(['did:webvh:xyz:them.biset.md'])
  })

  // An OLD Conversation Group thread (mls: threadId, retired from active
  // deployment) has no special case any more: main.ts's sendReply dropped
  // its `mls:` send branch entirely, so this now falls through to the
  // generic per-participant union like any other thread -- landing the
  // reply on the real DIDs the old messages carried (mimi-content-projector.ts's
  // old projector always wrote actual member DIDs, never the group address
  // itself), which sendReply then routes to 1:1 DIDComm chat or a fresh
  // DIDComm group chat depending on how many there are. Not a crash, just a
  // forward-migration off a retired transport.
  test('an old Conversation Group thread (mls: threadId) replies to its participants, not the dead group address', () => {
    const thread = [
      msg({ from: 'did:webvh:abc:alice.biset.md', to_addrs: ['did:webvh:xyz:bob.biset.md', 'did:webvh:def:carol.biset.md'], thread_id: 'mls:group-1', message_id: 'm1', ts: 1 }),
      msg({ from: 'did:webvh:xyz:bob.biset.md', to_addrs: ['did:webvh:abc:alice.biset.md', 'did:webvh:def:carol.biset.md'], thread_id: 'mls:group-1', message_id: 'm2', ts: 2 }),
    ]
    const { toAddrs } = computeReplyContext(thread, ['me@mail.biset.md', 'did:webvh:abc:alice.biset.md'])
    expect(toAddrs.sort()).toEqual(['did:webvh:def:carol.biset.md', 'did:webvh:xyz:bob.biset.md'])
  })
})
