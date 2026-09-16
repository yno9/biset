import { describe, expect, test } from 'bun:test'
import { MarkdownSelfWriteGuard, markdownStatusMutation, markdownThreadFilename, parseMarkdownThread, renderMarkdownThread } from '../../src/client/store/vault/markdown-mirror.ts'
import { emailSetToVaultMutationIntents } from '../../src/client/store/projection/mutations.ts'

const email = { id: 'e1', threadId: 'thread-1', receivedAt: '2026-09-16T01:02:00.000Z', mailboxIds: { inbox: true as const }, keywords: {}, from: [{ email: 'bob@example.com' }], to: [{ email: 'alice@example.com' }], subject: 'Hello' }
describe('Markdown projection mirror', () => {
  test('round-trips frontmatter and preserves the draft region', async () => {
    const rendered = await renderMarkdownThread('alice@example.com', [email], async () => 'message body', 'my draft')
    expect(parseMarkdownThread(rendered)).toEqual({ frontmatter: { subject: 'Hello', contact: 'bob@example.com', id: 'thread-1', status: '' }, draft: 'my draft' })
  })
  test('unread prefix changes deterministically and self writes are consumed once', () => {
    expect(markdownThreadFilename('alice@example.com', [email])).toStartWith('_')
    expect(markdownThreadFilename('alice@example.com', [{ ...email, keywords: { '$seen': true as const } }])).not.toStartWith('_')
    const guard = new MarkdownSelfWriteGuard(); guard.note('inbox/a.md', 'one')
    expect(guard.consumeIfSelfWrite('inbox/a.md', 'one')).toBe(true)
    expect(guard.consumeIfSelfWrite('inbox/a.md', 'one')).toBe(false)
  })
  test('status seen becomes a Layer 1 keyword.set intent', () => {
    const candidate = { ...email, keywords: {} }
    const request = markdownStatusMutation('seen', [candidate], { state: '', mailboxes: [], emails: [candidate] })!
    expect(emailSetToVaultMutationIntents(request)).toEqual([{ kind: 'keyword.set', targetIds: ['e1'], payload: { emailId: 'e1', keywords: { '$seen': true } } }])
    expect(candidate.keywords).toEqual({})
  })
})
