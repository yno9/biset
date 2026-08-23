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

  test('rejects a duplicate message.add rather than silently converging (dedup is the store\'s job, not the reducer\'s)', () => {
    const base = { mailboxes: [], emails: [] }
    const add = {
      event: event({ id: 'event-add-1', kind: 'message.add', targetIds: ['email-1'], objectRefs: ['metadata-1', 'raw-rfc5322-1'] }),
      plaintext: plaintext('message.add', ['email-1'], {
        email: { id: 'email-1', blobId: 'raw-rfc5322-1', threadId: 'thread-1', mailboxIds: {}, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' },
      }),
    }
    // The exact same record twice in one batch -- if the reducer silently
    // deduped this, it would mask a bug in the caller (event storage's own
    // unique keyPath is what's actually supposed to prevent this from ever
    // happening); it must fail loudly instead.
    expect(() => reduceLocalJmapProjection('did:web:alice.example', base, [add, add])).toThrow('conflicts with an existing email')
  })

  test('two devices writing to the same email while offline converge to the same result regardless of delivery order', () => {
    const identityId = 'did:web:alice.example'
    const base = {
      mailboxes: [],
      emails: [{ id: 'email-1', threadId: 'thread-1', mailboxIds: {}, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' }],
    }
    // Device A set a keyword at 00:00; device B set a DIFFERENT keyword one
    // minute later, on the same email, neither having seen the other's
    // write (both offline at the time) -- keyword.set replaces the whole
    // keywords object, so this is a real conflict, not a merge.
    const fromDeviceA = {
      event: event({ id: 'event-a', actorDeviceId: 'device-a', actorSeq: 5, kind: 'keyword.set', targetIds: ['email-1'], createdAt: '2026-08-21T00:00:00.000Z' }),
      plaintext: plaintext('keyword.set', ['email-1'], { emailId: 'email-1', keywords: { '$seen': true } }),
    }
    const fromDeviceB = {
      event: event({ id: 'event-b', actorDeviceId: 'device-b', actorSeq: 3, kind: 'keyword.set', targetIds: ['email-1'], createdAt: '2026-08-21T00:01:00.000Z' }),
      plaintext: plaintext('keyword.set', ['email-1'], { emailId: 'email-1', keywords: { flagged: true } }),
    }
    const deliveredAThenB = reduceLocalJmapProjection(identityId, base, [fromDeviceA, fromDeviceB])
    const deliveredBThenA = reduceLocalJmapProjection(identityId, base, [fromDeviceB, fromDeviceA])
    // Convergence: the array order sync happened to deliver records in must
    // not affect the final state.
    expect(deliveredAThenB).toEqual(deliveredBThenA)
    // The later write (device B, createdAt 00:01) wins.
    expect(deliveredAThenB.emails[0]!.keywords).toEqual({ flagged: true })
  })

  test('an interrupted-then-resumed transfer, folded incrementally in two batches, converges to the same projection as one uninterrupted batch', () => {
    const identityId = 'did:web:alice.example'
    const base = { mailboxes: [], emails: [] }
    const add = {
      event: event({ id: 'event-add-1', kind: 'message.add', targetIds: ['email-1'], objectRefs: ['metadata-1', 'raw-rfc5322-1'], createdAt: '2026-08-21T00:00:00.000Z' }),
      plaintext: plaintext('message.add', ['email-1'], {
        email: { id: 'email-1', blobId: 'raw-rfc5322-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' },
      }),
    }
    const mailboxUpdate = {
      event: event({ id: 'event-mb-1', kind: 'mailbox.set', targetIds: ['email-1'], createdAt: '2026-08-21T00:01:00.000Z' }),
      plaintext: plaintext('mailbox.set', ['email-1'], { emailId: 'email-1', mailboxIds: { archive: true } }),
    }
    const tombstone = {
      event: event({ id: 'event-ts-1', kind: 'message.tombstone', targetIds: ['email-1'], createdAt: '2026-08-21T00:02:00.000Z' }),
      plaintext: plaintext('message.tombstone', ['email-1'], { emailId: 'email-1' }),
    }
    const allRecords = [add, mailboxUpdate, tombstone]

    const oneShot = reduceLocalJmapProjection(identityId, base, allRecords)

    // The same records, but delivered as two separate batches the way a
    // transfer interrupted after the first chunk and resumed later would --
    // each batch only ever contains records whose target the PRIOR batch
    // already resolved (message.add lands no later than any mutation of the
    // same email), which is exactly what commitRestoreTransferChunk's own
    // "commit raw records now, run rebuildLocalJmapProjection once at the
    // end" design guarantees in production.
    const afterFirstChunk = reduceLocalJmapProjection(identityId, base, [add, mailboxUpdate])
    const afterSecondChunk = reduceLocalJmapProjection(
      identityId,
      { mailboxes: afterFirstChunk.mailboxes, emails: afterFirstChunk.emails },
      [tombstone],
    )
    expect(afterSecondChunk.emails).toEqual(oneShot.emails)
    expect(afterSecondChunk.mailboxes).toEqual(oneShot.mailboxes)
    expect(afterSecondChunk.state).toBe(oneShot.state)
  })

  test('fails closed on a mutation kind with no projection rule instead of silently dropping it', () => {
    // VaultEventKind (protocol/vault.ts) reserves kinds (reaction.set here)
    // no write path produces yet and this reducer has no rule for -- a
    // future/foreign device emitting one must not have it silently vanish
    // from sync while everything else appears to succeed.
    const base = {
      mailboxes: [],
      emails: [{ id: 'email-1', threadId: 'thread-1', mailboxIds: {}, keywords: {}, receivedAt: '2026-08-21T00:00:00.000Z' }],
    }
    expect(() => reduceLocalJmapProjection('did:web:alice.example', base, [{
      event: event({ kind: 'reaction.set', targetIds: ['email-1'], objectRefs: ['object-a'] }),
      plaintext: plaintext('reaction.set', ['email-1'], { emailId: 'email-1', emoji: '👍' }),
    }])).toThrow('has no Local JMAP projection rule')
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
