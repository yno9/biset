import { describe, expect, test } from 'bun:test'
import { computeReplyContext } from '../src/mail/message-view.ts'
import type { ProcessedMessage } from '../src/mail/message-view.ts'

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
})
