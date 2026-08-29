import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { buildMailRelationshipCredential, type MailRelationshipCredentialV1 } from '../../src/vault/mail-relationship-credential.ts'
import { MailRelationshipCredentialReader } from '../../src/vault/mail-relationship-credential-reader.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'

const identityId = 'did:web:alice.example'
const segmentId = 'segment-1'
const segmentKey = createSegmentKey()
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('mail relationship credential vault reader', () => {
  test('selects the unique unsuperseded credential per mediator while retaining history', async () => {
    const old = await record(1, credential('https://mail-mediator.example', 'did:peer:2.old', '2026-08-22T00:00:00.000Z'))
    const current = await record(2, credential('https://mail-mediator.example', 'did:peer:2.new', '2026-08-22T01:00:00.000Z', old.credential.relationshipDid))
    const reader = makeReader([old, current])

    expect((await reader.readAll()).map(v => v.relationshipDid)).toEqual([old.credential.relationshipDid, current.credential.relationshipDid])
    expect((await reader.readCurrentFor('https://mail-mediator.example'))?.relationshipDid).toBe(current.credential.relationshipDid)
  })

  test('scopes readCurrentFor by mediatorUrl -- an unrelated mediator has no bearing', async () => {
    const a = await record(1, credential('https://mail-mediator-a.example', 'did:peer:2.a', '2026-08-22T00:00:00.000Z'))
    const reader = makeReader([a])
    expect(await reader.readCurrentFor('https://mail-mediator-b.example')).toBeUndefined()
    expect((await reader.readCurrentFor('https://mail-mediator-a.example'))?.relationshipDid).toBe('did:peer:2.a')
  })

  test('fails closed when two credentials for the same mediator have no rotation relation', async () => {
    const first = await record(1, credential('https://mail-mediator.example', 'did:peer:2.one', '2026-08-22T00:00:00.000Z'))
    const second = await record(2, credential('https://mail-mediator.example', 'did:peer:2.two', '2026-08-22T01:00:00.000Z'))
    await expect(makeReader([first, second]).readCurrentFor('https://mail-mediator.example')).rejects.toThrow('ambiguous')
  })

  test('rejects a credential event whose signature is no longer valid', async () => {
    const value = await record(1, credential('https://mail-mediator.example', 'did:peer:2.one', '2026-08-22T00:00:00.000Z'))
    const tampered = { ...value, event: { ...value.event, signature: new Uint8Array([0]) } }
    await expect(makeReader([tampered]).readAll()).rejects.toThrow('signature')
  })
})

function credential(mediatorUrl: string, relationshipDid: string, createdAt: string, supersedesRelationshipDid?: string): MailRelationshipCredentialV1 {
  return {
    version: 1, kind: 'credential.mail-relationship', identityId, mediatorUrl, address: 'y@biset.md',
    relationshipDid, privateKey: new Uint8Array(32).fill(1), edPrivateKey: new Uint8Array(32).fill(2), routeGeneration: 'gen-1',
    createdAt, ...(supersedesRelationshipDid === undefined ? {} : { supersedesRelationshipDid }),
  }
}

async function record(actorSeq: number, value: MailRelationshipCredentialV1) {
  return buildMailRelationshipCredential(value, { identityId, actorDeviceId: 'device-a', actorSeq, parents: actorSeq === 1 ? [] : ['event-1'], segmentId, segmentKey }, signer)
}

function makeReader(records: Awaited<ReturnType<typeof record>>[]): MailRelationshipCredentialReader {
  const objects = new Map(records.map(value => [value.object.objectId, { ...value.object, identityId }]))
  return new MailRelationshipCredentialReader({
    identityId,
    objects: { async readObject(_identityId, objectId) { return objects.get(objectId) } },
    events: { async readCredentialEvents() { return records.map(value => ({ ...value.event, identityId, targetIds: [...value.event.targetIds], objectRefs: [...value.event.objectRefs], parents: [...value.event.parents], signature: value.event.signature.slice() })) } },
    segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
    verifier: signer,
  })
}
