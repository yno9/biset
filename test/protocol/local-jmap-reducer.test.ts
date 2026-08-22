import { describe, expect, test } from 'bun:test'
import { canonicalBytes } from '../../src/protocol/canonical.ts'
import { decodeVaultMutation, reduceLocalJmapProjection } from '../../src/local-jmap/reducer.ts'
import type { VaultEventV1 } from '../../src/protocol/vault.ts'

function event(overrides: Partial<VaultEventV1> = {}): VaultEventV1 {
  return {
    version: 1,
    id: 'event-a',
    identityId: 'did:web:alice.example',
    actorDeviceId: 'device-a',
    actorSeq: 1,
    kind: 'keyword.set',
    targetIds: ['email-1'],
    objectRefs: ['object-a'],
    parents: [],
    createdAt: '2026-08-21T00:00:00.000Z',
    signature: new Uint8Array([1]),
    ...overrides,
  }
}

function plaintext(kind: string, targetIds: string[], payload: object): Uint8Array {
  return canonicalBytes({ version: 1, kind, targetIds, payload })
}

describe('Local JMAP projection reducer', () => {
  test('applies sorted immutable mailbox/keyword changes and makes tombstones win', () => {
    const base = {
      mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 2, unreadEmails: 1 }],
      emails: [
        { id: 'email-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' },
        { id: 'email-2', threadId: 'thread-2', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' },
      ],
    }
    const projection = reduceLocalJmapProjection('did:web:alice.example', base, [
      { event: event({ id: 'event-z', actorSeq: 3, kind: 'message.tombstone', targetIds: ['email-2'], createdAt: '2026-08-21T00:02:00.000Z' }), plaintext: plaintext('message.tombstone', ['email-2'], { emailId: 'email-2' }) },
      { event: event({ id: 'event-b', actorSeq: 2, kind: 'mailbox.set', targetIds: ['email-1'], createdAt: '2026-08-21T00:01:00.000Z' }), plaintext: plaintext('mailbox.set', ['email-1'], { emailId: 'email-1', mailboxIds: { archive: true } }) },
      { event: event({ id: 'event-a', actorSeq: 1, kind: 'keyword.set', targetIds: ['email-2'] }), plaintext: plaintext('keyword.set', ['email-2'], { emailId: 'email-2', keywords: { '$seen': true } }) },
    ])
    expect(projection.emails).toEqual([{ id: 'email-1', threadId: 'thread-1', mailboxIds: { archive: true }, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' }])
    expect(projection.state).toStartWith('sha256:')
  })

  test('refuses decrypted content that does not agree with its signed event', () => {
    const signedEvent = event({ kind: 'mailbox.set' })
    expect(() => decodeVaultMutation(signedEvent, plaintext('keyword.set', ['email-1'], { emailId: 'email-1', keywords: {} }))).toThrow('does not match')
  })

  test('adds a mail item only when its metadata binds the second reference as the raw RFC 5322 blob', () => {
    const base = { mailboxes: [{ id: 'inbox', name: 'Inbox', totalEmails: 0, unreadEmails: 0 }], emails: [] }
    const projection = reduceLocalJmapProjection('did:web:alice.example', base, [{
      event: event({ kind: 'message.add', targetIds: ['email-1'], objectRefs: ['metadata-1', 'raw-rfc5322-1'] }),
      plaintext: plaintext('message.add', ['email-1'], {
        email: {
          id: 'email-1', blobId: 'raw-rfc5322-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {},
          receivedAt: '2026-08-21T00:00:00.000Z', subject: 'Hello', size: 123,
        },
      }),
    }])
    expect(projection.emails).toEqual([{
      id: 'email-1', blobId: 'raw-rfc5322-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {},
      receivedAt: '2026-08-21T00:00:00.000Z', subject: 'Hello', size: 123,
    }])
    expect(projection.mailboxes[0]).toMatchObject({ totalEmails: 1, unreadEmails: 1 })
  })

  test('refuses message metadata which points at a different raw RFC 5322 object', () => {
    const base = { mailboxes: [], emails: [] }
    expect(() => reduceLocalJmapProjection('did:web:alice.example', base, [{
      event: event({ kind: 'message.add', targetIds: ['email-1'], objectRefs: ['metadata-1', 'raw-rfc5322-1'] }),
      plaintext: plaintext('message.add', ['email-1'], {
        email: { id: 'email-1', blobId: 'other-blob', threadId: 'thread-1', mailboxIds: {}, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' },
      }),
    }])).toThrow('does not bind')
  })
})
