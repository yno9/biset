import { describe, expect, test } from 'bun:test'
import { createWalletDidCommOutbox } from '../src/wallet/didcomm-outbox.ts'

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
})
