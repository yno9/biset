import { describe, expect, test } from 'bun:test'
import { IndexedDbLocalJmapReadModel } from '../../src/local-jmap/indexeddb.ts'
import { localJmapSnapshotFromProjection } from '../../src/local-jmap/gateway.ts'

const identityId = 'did:web:alice.example'
const projection = {
  version: 1 as const,
  identityId,
  state: 'vault-root-1',
  mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 1, unreadEmails: 1 }],
  emails: [{ id: 'email-1', blobId: 'blob-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' }],
}

describe('IndexedDbLocalJmapReadModel', () => {
  test('adapts a durable vault projection without giving JMAP a crypto dependency', async () => {
    const downloads: string[] = []
    const model = new IndexedDbLocalJmapReadModel(
      { async readProjection(requestedIdentity) { return requestedIdentity === identityId ? projection : undefined } },
      identityId,
      { async download(requestedIdentity, blobId) { downloads.push(`${requestedIdentity}:${blobId}`); return new Uint8Array([9]) } },
    )
    expect(await model.snapshot()).toMatchObject({ state: 'vault-root-1', emails: [{ id: 'email-1' }] })
    expect(await model.download('blob-1')).toEqual(new Uint8Array([9]))
    expect(downloads).toEqual(['did:web:alice.example:blob-1'])
  })

  test('rejects a projection that belongs to another identity', () => {
    expect(() => localJmapSnapshotFromProjection({ ...projection, identityId: 'did:web:bob.example' }, identityId)).toThrow('invalid version, identity, or state')
  })
})
