import { describe, expect, test } from 'bun:test'
import { LocalJmapGateway, LocalJmapTransport, MemoryLocalJmapReadModel } from '../../src/client/store/projection/gateway.ts'

const model = new MemoryLocalJmapReadModel({
  state: 'vault-root-1',
  mailboxes: [{ id: 'inbox', name: 'Inbox', role: 'inbox', totalEmails: 2, unreadEmails: 1 }],
  emails: [
    { id: 'email-old', blobId: 'blob-old', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-20T00:00:00.000Z', subject: 'Old' },
    { id: 'email-new', blobId: 'blob-new', threadId: 'thread-2', mailboxIds: { inbox: true }, keywords: { '$seen': true }, receivedAt: '2026-08-21T00:00:00.000Z', subject: 'New' },
  ],
}, new Map([['blob-new', new Uint8Array([1, 2, 3, 4])]]))

function transport(): LocalJmapTransport {
  return new LocalJmapTransport(new LocalJmapGateway({
    accountId: 'biset:did:web:alice.example',
    identityId: 'did:web:alice.example',
    readModel: model,
  }))
}

describe('LocalJmapGateway', () => {
  test('presents a vault projection through ordinary JMAP reads', async () => {
    const local = transport()
    expect((await local.session()).primaryAccounts).toEqual({ 'urn:ietf:params:jmap:mail': 'biset:did:web:alice.example' })
    const response = await local.call<{ methodResponses: Array<[string, Record<string, unknown>, string]> }>([
      { name: 'Mailbox/get', arguments: { accountId: 'biset:did:web:alice.example' }, callId: 'mailboxes' },
      { name: 'Email/query', arguments: { accountId: 'biset:did:web:alice.example', filter: { inMailbox: 'inbox' }, limit: 1 }, callId: 'query' },
      { name: 'Email/get', arguments: { accountId: 'biset:did:web:alice.example', ids: ['email-new'] }, callId: 'emails' },
    ])
    expect(response.methodResponses[0][1].list).toEqual([{ id: 'inbox', name: 'Inbox', role: 'inbox', totalEmails: 2, unreadEmails: 1 }])
    expect(response.methodResponses[1][1].ids).toEqual(['email-new'])
    expect(response.methodResponses[2][1].list).toMatchObject([{ id: 'email-new', subject: 'New' }])
  })

  test('keeps blob access local and returns JMAP errors for a different account or unknown method', async () => {
    const local = transport()
    expect(await local.download('blob-new', { start: 1, end: 2 })).toEqual(new Uint8Array([2, 3]))
    const response = await local.call<{ methodResponses: Array<[string, Record<string, unknown>, string]> }>([
      { name: 'Email/get', arguments: { accountId: 'other' }, callId: 'other' },
      { name: 'Unknown/method', arguments: {}, callId: 'unknown' },
    ])
    expect(response.methodResponses.map(response => response[1].type)).toEqual(['accountNotFound', 'unknownMethod'])
  })
})
