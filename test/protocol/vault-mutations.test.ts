import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { emailSetToVaultMutationIntents } from '../../src/local-jmap/mutations.ts'
import { decryptVaultObject } from '../../src/vault/objects.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import { verifyVaultEvent, type VaultEventSigner } from '../../src/vault/events.ts'
import { buildVaultMutation, mutationObjectAad } from '../../src/vault/mutations.ts'

const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('vault mutations', () => {
  test('turns a JMAP mutation intent into an encrypted object and signed event', async () => {
    const segmentKey = createSegmentKey()
    const [intent] = emailSetToVaultMutationIntents({ update: { 'email-1': { keywords: { '$seen': true } } } })
    const record = await buildVaultMutation(intent, {
      identityId: 'did:web:alice.example',
      actorDeviceId: 'device-a',
      actorSeq: 3,
      parents: ['event-previous'],
      segmentId: 'segment-1',
      segmentKey,
      createdAt: '2026-08-21T00:00:00.000Z',
    }, signer)

    expect(record.event.objectRefs).toEqual([record.object.objectId])
    expect(record.event.kind).toBe('keyword.set')
    expect(await verifyVaultEvent(record.event, signer)).toBe(true)
    const plaintext = await decryptVaultObject(segmentKey, record.object)
    expect(JSON.parse(new TextDecoder().decode(plaintext))).toEqual({
      version: 1,
      kind: 'keyword.set',
      targetIds: ['email-1'],
      payload: { emailId: 'email-1', keywords: { '$seen': true } },
    })
  })

  test('binds the encrypted mutation object to its identity, segment, kind, and target', async () => {
    const aad = mutationObjectAad('did:web:alice.example', 'segment-1', 'mailbox.set', ['email-1'])
    expect(aad).not.toEqual(mutationObjectAad('did:web:alice.example', 'segment-1', 'mailbox.set', ['email-2']))
  })
})
