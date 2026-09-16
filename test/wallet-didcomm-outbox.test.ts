import { describe, expect, test } from 'bun:test'
import { createWalletDidCommOutbox } from '../src/client/identity/wallet/didcomm-outbox.ts'

const identityId = 'did:webvh:wallet:alice.test.example'

describe('Wallet DIDComm outbox', () => {
  test('retains a failed private send, then retries the same message id and removes it only after success', async () => {
    const item = {
      identityId, outboundEventId: 'event-1' as never, emailId: 'email-1', messageId: 'message-1',
      toDid: 'did:webvh:wallet:bob.test.example', createdAt: '2026-09-05T12:00:00.000Z', attempts: 0,
    }
    const queued = [item]
    const attempts: string[] = []
    const removed: string[] = []
    const commits: unknown[][] = []
    let sends = 0
    const outbox = createWalletDidCommOutbox({
      identityId,
      store: {
        async readDidCommOutbox() { return [...queued] },
        async noteDidCommOutboxAttempt(_identityId, _eventId, _toDid, attemptedAt) { attempts.push(attemptedAt) },
        async removeDidCommOutbox() { removed.push('email-1'); queued.splice(0, 1) },
      },
      readModel: {
        async snapshot() {
          return {
            state: 's1', mailboxes: [],
            emails: [{ id: 'email-1', blobId: 'blob-1', threadId: 'didcomm-thread', mailboxIds: { outbox: true }, keywords: {}, receivedAt: item.createdAt, sentAt: item.createdAt, subject: 'hello' }],
          }
        },
        async download(blobId) { expect(blobId).toBe('blob-1'); return new TextEncoder().encode('hello from retry') },
      },
      mutationSink: { async commitIntents(intents) { commits.push(intents); return {} } },
      ensureContact: async toDid => {
        expect(toDid).toBe(item.toDid)
        return {} as never
      },
      send: async (_contact, content, subject, message) => {
        sends += 1
        expect(content).toBe('hello from retry')
        expect(subject).toBe('hello')
        expect(message).toEqual({ id: 'message-1', sentAt: item.createdAt })
        return sends === 1 ? { ok: false, error: 'offline' } : { ok: true }
      },
      onError() {},
    })

    await outbox.flush()
    expect(attempts).toHaveLength(1)
    expect(removed).toEqual([])
    expect(commits).toEqual([])

    await outbox.flush()
    expect(attempts).toHaveLength(2)
    expect(removed).toEqual(['email-1'])
    expect(commits).toEqual([[
      { kind: 'transport.result', targetIds: ['email-1'], payload: { emailId: 'email-1', status: 'accepted', occurredAt: expect.any(String), transport: 'didcomm' } },
      { kind: 'mailbox.set', targetIds: ['email-1'], payload: { emailId: 'email-1', mailboxIds: { sent: true } } },
    ]])
  })

  test('a stalled row does not block a newly queued message from flushing', async () => {
    const first = { identityId, outboundEventId: 'event-1' as never, emailId: 'email-1', messageId: 'message-1', toDid: 'did:example:bob', createdAt: '2026-09-16T00:00:00.000Z', attempts: 0 }
    const second = { ...first, outboundEventId: 'event-2' as never, emailId: 'email-2', messageId: 'message-2' }
    const queued = [first]; const sent: string[] = []
    let releaseFirst!: () => void; const firstGate = new Promise<void>(resolve => { releaseFirst = resolve })
    const outbox = createWalletDidCommOutbox({
      identityId,
      store: { async readDidCommOutbox() { return [...queued] }, async noteDidCommOutboxAttempt() {}, async removeDidCommOutbox(_i, eventId) { const index = queued.findIndex(row => row.outboundEventId === eventId); if (index >= 0) queued.splice(index, 1) } },
      readModel: { async snapshot() { return { state: '', mailboxes: [], emails: queued.map(row => ({ id: row.emailId, blobId: `blob-${row.emailId}`, threadId: 'thread', mailboxIds: { outbox: true as const }, keywords: {}, receivedAt: row.createdAt })) } }, async download() { return new TextEncoder().encode('body') } },
      mutationSink: { async commitIntents() { return {} } }, ensureContact: async () => ({} as never),
      async send(_contact, _content, _subject, message) { sent.push(message.id); if (message.id === first.messageId) await firstGate; return { ok: true } }, onError() {},
    })
    const firstFlush = outbox.flush(); await new Promise(resolve => setTimeout(resolve, 0))
    queued.push(second); await outbox.flush()
    expect(sent).toContain('message-2')
    releaseFirst(); await firstFlush
  })

  test('a recipient-scoped flush cannot send another group member before their invite', async () => {
    const bob = { identityId, outboundEventId: 'event-bob' as never, emailId: 'email-bob', messageId: 'message-bob', toDid: 'did:example:bob', createdAt: '2026-09-16T00:00:00.000Z', attempts: 0 }
    const carol = { ...bob, outboundEventId: 'event-carol' as never, emailId: 'email-carol', messageId: 'message-carol', toDid: 'did:example:carol' }
    const queued = [bob, carol]
    const sent: string[] = []
    const outbox = createWalletDidCommOutbox({
      identityId,
      store: {
        async readDidCommOutbox() { return [...queued] },
        async noteDidCommOutboxAttempt() {},
        async removeDidCommOutbox(_identity, eventId) { const index = queued.findIndex(row => row.outboundEventId === eventId); if (index >= 0) queued.splice(index, 1) },
      },
      readModel: {
        async snapshot() { return { state: '', mailboxes: [], emails: queued.map(row => ({ id: row.emailId, blobId: `blob-${row.emailId}`, threadId: 'didcomm-group:group-1', mailboxIds: { outbox: true as const }, keywords: {}, receivedAt: row.createdAt })) } },
        async download() { return new TextEncoder().encode('group body') },
      },
      mutationSink: { async commitIntents() { return {} } },
      ensureContact: async () => ({} as never),
      async send(_contact, _content, _subject, message) { sent.push(message.id); return { ok: true } },
      onError() {},
    })

    await outbox.flush(bob.toDid)
    expect(sent).toEqual(['message-bob'])
    expect(queued.map(row => row.messageId)).toEqual(['message-carol'])
  })

  test('sends from durable Vault object references when the derived projection is missing', async () => {
    const item = {
      identityId, outboundEventId: 'event-orphan' as never, emailId: 'email-orphan',
      blobId: 'body-blob', metadataBlobId: 'metadata-blob', messageId: 'message-orphan',
      toDid: 'did:example:carol', createdAt: '2026-09-16T00:00:00.000Z', attempts: 0,
    }
    let removed = false
    const sent: Array<{ content: string; threadId: string }> = []
    const outbox = createWalletDidCommOutbox({
      identityId,
      store: {
        async readDidCommOutbox() { return removed ? [] : [item] },
        async noteDidCommOutboxAttempt() {},
        async removeDidCommOutbox() { removed = true },
      },
      readModel: {
        async snapshot() { return { state: '', mailboxes: [], emails: [] } },
        async download(blobId) {
          if (blobId === 'body-blob') return new TextEncoder().encode('recovered body')
          if (blobId === 'metadata-blob') return new TextEncoder().encode(JSON.stringify({
            version: 1, kind: 'message.add', targetIds: ['email-orphan'],
            payload: { email: { id: 'email-orphan', blobId: 'body-blob', threadId: 'didcomm-group:group-1', sentAt: item.createdAt } },
          }))
          throw new Error('unexpected blob')
        },
      },
      mutationSink: { async commitIntents() { return {} } },
      ensureContact: async () => ({} as never),
      async send(_contact, content, _subject, _message, threadId) { sent.push({ content, threadId }); return { ok: true } },
      onError(error) { throw error },
    })

    await outbox.flush()
    expect(sent).toEqual([{ content: 'recovered body', threadId: 'didcomm-group:group-1' }])
    expect(removed).toBe(true)
  })
})
