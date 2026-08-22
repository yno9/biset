import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { decryptVaultObject } from '../../src/vault/objects.ts'
import { buildMailMessageAdd, rawRfc5322ObjectAad } from '../../src/vault/mail-message.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { verifyVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'

const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('mail message vault record', () => {
  test('binds encrypted JMAP metadata and unchanged raw RFC 5322 bytes in one signed message.add event', async () => {
    const segmentKey = createSegmentKey()
    const raw = new TextEncoder().encode('From: alice@example.test\r\nSubject: Hello\r\n\r\nmail bytes\r\n')
    const record = await buildMailMessageAdd({
      email: {
        id: 'email-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {},
        receivedAt: '2026-08-21T00:00:00.000Z', subject: 'Hello', size: raw.length,
      },
      rawRfc5322: raw,
    }, {
      identityId: 'did:web:alice.example', actorDeviceId: 'device-a', actorSeq: 5, parents: ['event-previous'],
      segmentId: 'segment-1', segmentKey, createdAt: '2026-08-21T00:00:00.000Z',
    }, signer)

    expect(record.event.objectRefs).toEqual([record.metadataObject.objectId, record.rawRfc5322Object.objectId])
    expect(await verifyVaultEvent(record.event, signer)).toBe(true)
    expect(await decryptVaultObject(segmentKey, record.rawRfc5322Object)).toEqual(raw)
    expect(record.rawRfc5322Object.aad).toEqual(rawRfc5322ObjectAad('did:web:alice.example', 'segment-1'))
    expect(JSON.parse(new TextDecoder().decode(await decryptVaultObject(segmentKey, record.metadataObject)))).toEqual({
      version: 1,
      kind: 'message.add',
      targetIds: ['email-1'],
      payload: {
        email: {
          id: 'email-1', blobId: record.rawRfc5322Object.objectId, threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {},
          receivedAt: '2026-08-21T00:00:00.000Z', subject: 'Hello', size: raw.length,
        },
      },
    })
  })
})
