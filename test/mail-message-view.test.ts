// Unit coverage for the vault UI's message-pipeline module (PLAN.md §7):
// threading.ts's union-find port (unchanged logic, just relocated) and the
// new emailToMessageView bridge from LocalJmapEmail + raw RFC5322 bytes.
import { describe, expect, test } from 'bun:test'
import { computeThreadKeys, emailToMessageView } from '../src/mail/message-view.ts'
import type { LocalJmapEmail } from '../src/local-jmap/gateway.ts'

describe('computeThreadKeys', () => {
  test('groups replies that share an explicit thread_id', () => {
    const keys = computeThreadKeys([
      { message_id: 'a', thread_id: 't1' },
      { message_id: 'b', thread_id: 't1', in_reply_to: 'a' },
    ])
    expect(keys.get('a')).toBe(keys.get('b'))
  })

  test('merges two distinct thread_ids via a shared phantom parent (DeltaChat-hidden references)', () => {
    const keys = computeThreadKeys([
      { message_id: 'child-1', thread_id: 't1', in_reply_to: 'missing-parent' },
      { message_id: 'child-2', thread_id: 't2', in_reply_to: 'missing-parent' },
    ])
    expect(keys.get('child-1')).toBe(keys.get('child-2'))
  })

  test('is deterministic regardless of input order (lexicographically-smallest-root tie-break)', () => {
    const forward = computeThreadKeys([
      { message_id: 'a', thread_id: 'zzz' },
      { message_id: 'b', thread_id: 'aaa', in_reply_to: 'a' },
    ])
    const backward = computeThreadKeys([
      { message_id: 'b', thread_id: 'aaa', in_reply_to: 'a' },
      { message_id: 'a', thread_id: 'zzz' },
    ])
    expect(forward.get('a')).toBe(backward.get('a'))
    expect(forward.get('b')).toBe(backward.get('b'))
  })

  test('leaves unrelated messages in separate threads', () => {
    const keys = computeThreadKeys([
      { message_id: 'a', thread_id: 't1' },
      { message_id: 'b', thread_id: 't2' },
    ])
    expect(keys.get('a')).not.toBe(keys.get('b'))
  })
})

describe('emailToMessageView', () => {
  const baseEmail: LocalJmapEmail = {
    id: 'msg-1',
    blobId: 'blob-1',
    threadId: 'thread-1',
    mailboxIds: { inbox: true },
    keywords: {},
    receivedAt: '2026-08-24T00:00:00.000Z',
    from: [{ email: 'alice@example.com', name: 'Alice' }],
    to: [{ email: 'bob@example.com' }],
    subject: 'hello',
  }

  test('uses LocalJmapEmail metadata for from/to/subject, not a re-parse of the raw blob', () => {
    const raw = new TextEncoder().encode('Subject: different subject in the blob\r\n\r\nbody text')
    const view = emailToMessageView(baseEmail, raw)
    expect(view.from).toBe('alice@example.com')
    expect(view.from_name).toBe('Alice')
    expect(view.to_addrs).toEqual(['bob@example.com'])
    expect(view.subject).toBe('hello')
  })

  test('recovers threading headers and plain-text body from the raw RFC5322 blob', () => {
    const raw = new TextEncoder().encode(
      'Message-Id: <m1@example.com>\r\nIn-Reply-To: <m0@example.com>\r\nReferences: <m0@example.com>\r\n\r\nhi there'
    )
    const view = emailToMessageView(baseEmail, raw)
    expect(view.message_id).toBe('m1@example.com')
    expect(view.in_reply_to).toBe('m0@example.com')
    expect(view.references).toEqual(['m0@example.com'])
    expect(view.body).toBe('hi there')
    expect(view.jmap_id).toBe('msg-1')
    expect(view.thread_id).toBe('thread-1')
    expect(view.blob_id).toBe('blob-1')
  })

  test('falls back to the JMAP id when the raw blob has no Message-Id header', () => {
    const raw = new TextEncoder().encode('Subject: hello\r\n\r\nbody')
    const view = emailToMessageView(baseEmail, raw)
    expect(view.message_id).toBe('msg-1')
  })

  test('decodes a quoted-printable text/plain body', () => {
    const raw = new TextEncoder().encode(
      'Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nline one=\r\nline two'
    )
    const view = emailToMessageView(baseEmail, raw)
    expect(view.body).toBe('line oneline two')
  })

  test('picks the text/plain leaf out of a multipart/alternative body', () => {
    const raw = new TextEncoder().encode(
      'Content-Type: multipart/alternative; boundary="B"\r\n\r\n'
      + '--B\r\nContent-Type: text/plain\r\n\r\nplain body\r\n'
      + '--B\r\nContent-Type: text/html\r\n\r\n<p>html body</p>\r\n'
      + '--B--\r\n'
    )
    const view = emailToMessageView(baseEmail, raw)
    expect(view.body).toBe('plain body')
  })

  test('reflects $seen keyword', () => {
    const seenEmail: LocalJmapEmail = { ...baseEmail, keywords: { '$seen': true } }
    const raw = new TextEncoder().encode('Subject: hello\r\n\r\nbody')
    expect(emailToMessageView(seenEmail, raw).seen).toBe(true)
    expect(emailToMessageView(baseEmail, raw).seen).toBe(false)
  })
})
