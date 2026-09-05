import { describe, expect, test } from 'bun:test'
import type { LocalJmapEmail } from '../src/client/store/projection/gateway.ts'
import { reduceLocalJmapProjection } from '../src/client/store/projection/reducer.ts'
import { encodeVaultMutationObject } from '../src/client/store/vault/mutations.ts'
import type { VaultEventV1 } from '../src/shared/protocol/vault.ts'

const identityId = 'did:webvh:alice.example'
const email: LocalJmapEmail = {
  id: 'message-1',
  blobId: 'local-blob',
  threadId: 'thread-1',
  mailboxIds: { inbox: true },
  keywords: { $seen: true },
  receivedAt: '2026-08-28T00:00:01.000Z',
  sentAt: '2026-08-28T00:00:00.000Z',
  from: [{ email: 'did:example:bob' }],
  to: [{ email: identityId }],
  subject: 'hello',
}
const event: VaultEventV1 = {
  version: 1,
  id: 'event-1',
  identityId,
  actorDeviceId: 'device-a',
  actorSeq: 1,
  kind: 'message.add',
  targetIds: [email.id],
  objectRefs: ['metadata-object', 'coordinator-blob'],
  parents: [],
  createdAt: '2026-08-28T00:00:02.000Z',
  signature: new Uint8Array([1]),
}

describe('local JMAP reducer', () => {
  test('idempotently accepts the same message from transport and Coordinator', () => {
    const delivered = { ...email, blobId: 'coordinator-blob', mailboxIds: { inbox: true } as Record<string, true>, keywords: {}, receivedAt: '2026-08-28T00:00:02.000Z' }
    const result = reduceLocalJmapProjection(identityId, base(email), [{
      event,
      plaintext: messageAdd(delivered),
    }])

    expect(result.emails).toEqual([email])
  })

  test('rejects a reused message ID with different immutable metadata', () => {
    const delivered = { ...email, blobId: 'coordinator-blob', subject: 'different' }
    expect(() => reduceLocalJmapProjection(identityId, base(email), [{
      event,
      plaintext: messageAdd(delivered),
    }])).toThrow('conflicts with an existing email')
  })
})

function base(existing: LocalJmapEmail) {
  return {
    mailboxes: [{ id: 'inbox', name: 'Inbox', role: 'inbox', totalEmails: 1, unreadEmails: 0 }],
    emails: [existing],
  }
}

function messageAdd(value: LocalJmapEmail): Uint8Array {
  return encodeVaultMutationObject({
    kind: 'message.add',
    targetIds: [value.id],
    payload: { email: value },
  })
}
