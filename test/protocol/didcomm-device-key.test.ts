import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/shared/protocol/canonical.ts'
import { decryptVaultObject, createSegmentKey } from '../../src/vault/objects.ts'
import { createSegmentKeyWrap } from '../../src/vault/crypto.ts'
import { decodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import {
  buildDidCommDeviceKeyRecord,
  decodeDidCommDeviceKey,
  deviceKeyAad,
  type DidCommDeviceKeyV1,
} from '../../src/vault/didcomm-device-key.ts'
import { DidCommDeviceKeyVaultSink } from '../../src/vault/didcomm-device-key-sink.ts'
import { DidCommDeviceKeyReader } from '../../src/vault/didcomm-device-key-reader.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'

const identityId = 'did:web:alice.example'
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

function key(deviceKid: string, didCommKid: string, createdAt: string): DidCommDeviceKeyV1 {
  return { version: 1, kind: 'didcomm.device-key', identityId, deviceKid, didCommKid, createdAt }
}

describe('DIDComm device-key vault record', () => {
  test('encrypts a canonical pairing and binds it to identity, segment, and deviceKid', async () => {
    const segmentKey = new Uint8Array(32).fill(7)
    const record = await buildDidCommDeviceKeyRecord(
      key(`${identityId}#device-a`, `${identityId}#k_abc`, '2026-08-25T00:00:00.000Z'),
      { identityId, actorDeviceId: 'device-a', actorSeq: 1, parents: [], segmentId: 'segment-1', segmentKey },
      signer,
    )
    expect(record.event.kind).toBe('didcomm.device-key.set')
    expect(record.event.targetIds).toEqual([`${identityId}#device-a`])
    const plaintext = await decryptVaultObject(segmentKey, record.object)
    expect(decodeDidCommDeviceKey(plaintext)).toMatchObject({ deviceKid: `${identityId}#device-a`, didCommKid: `${identityId}#k_abc` })
    expect(record.object.aad).toEqual(deviceKeyAad(identityId, 'segment-1', `${identityId}#device-a`))
  })

  test('rejects a tampered pairing before it is trusted', () => {
    const bytes = new TextEncoder().encode(JSON.stringify({ ...key(`${identityId}#device-a`, `${identityId}#k_abc`, '2026-08-25T00:00:00.000Z'), didCommKid: `${identityId}#k_evil` }))
    expect(() => decodeDidCommDeviceKey(new Uint8Array([...bytes, 0]))).toThrow()
  })
})

describe('DIDComm device-key vault sink', () => {
  test('atomically queues an encrypted pairing for shared vault delivery without changing JMAP state', async () => {
    const segmentKey = createSegmentKey()
    const wrap = await createSegmentKeyWrap(new Uint8Array(32).fill(7), segmentKey, { identityId, selfGroupId: 'self-group-1', segmentId: 'segment-1', sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: '2026-08-25T00:00:00.000Z' }, signer)
    let committed: any
    const sink = new DidCommDeviceKeyVaultSink({
      identityId, actorDeviceId: 'device-a', async nextActorSeq() { return 1 }, async initialParents() { return [] },
      async activeSegment() { return { segmentId: 'segment-1', segmentKey, keyWraps: [wrap] } },
      async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } }, signer,
      committer: { async commitLocalMutation(input) { committed = input; return 'committed' } },
    })
    const result = await sink.store(key(`${identityId}#device-a`, `${identityId}#k_abc`, '2026-08-25T00:00:00.000Z'))
    expect(result.event.kind).toBe('didcomm.device-key.set')
    expect(committed.projection).toMatchObject({ state: 'state-1', emails: [] })
    const pack = decodeVaultDeliveryPack(committed.deliveryOutbox.payload)
    expect(pack.events).toMatchObject([{ kind: 'didcomm.device-key.set' }])
  })
})

describe('DIDComm device-key vault reader', () => {
  test('finds the pairing for a specific device kid among other vault event kinds', async () => {
    const segmentKey = createSegmentKey()
    const own = await buildDidCommDeviceKeyRecord(key(`${identityId}#device-a`, `${identityId}#k_abc`, '2026-08-25T00:00:00.000Z'), { identityId, actorDeviceId: 'device-a', actorSeq: 1, parents: [], segmentId: 'segment-1', segmentKey }, signer)
    const other = await buildDidCommDeviceKeyRecord(key(`${identityId}#device-b`, `${identityId}#k_def`, '2026-08-25T00:01:00.000Z'), { identityId, actorDeviceId: 'device-a', actorSeq: 2, parents: [own.event.id], segmentId: 'segment-1', segmentKey }, signer)
    const unrelatedEvent = { ...own.event, id: 'unrelated-event', kind: 'didcomm.control' as const, targetIds: ['not-a-device'] }

    const objects = new Map([own, other].map(record => [record.object.objectId, { ...record.object, identityId }]))
    const reader = new DidCommDeviceKeyReader({
      identityId,
      objects: { async readObject(_identityId, objectId) { return objects.get(objectId) } },
      events: { async readVaultEvents() { return [own.event, other.event, unrelatedEvent].map(event => ({ ...event, identityId })) }, async readVaultObjects() { return [] } },
      segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
      verifier: signer,
    })

    expect((await reader.readAll()).map(record => record.deviceKid).sort()).toEqual([`${identityId}#device-a`, `${identityId}#device-b`])
    expect((await reader.forDeviceKid(`${identityId}#device-b`))?.didCommKid).toBe(`${identityId}#k_def`)
    expect(await reader.forDeviceKid(`${identityId}#device-nonexistent`)).toBeUndefined()
  })

  test('rejects a pairing event whose signature is no longer valid', async () => {
    const segmentKey = createSegmentKey()
    const value = await buildDidCommDeviceKeyRecord(key(`${identityId}#device-a`, `${identityId}#k_abc`, '2026-08-25T00:00:00.000Z'), { identityId, actorDeviceId: 'device-a', actorSeq: 1, parents: [], segmentId: 'segment-1', segmentKey }, signer)
    const tampered = { ...value.event, signature: new Uint8Array([0]) }
    const objects = new Map([[value.object.objectId, { ...value.object, identityId }]])
    const reader = new DidCommDeviceKeyReader({
      identityId,
      objects: { async readObject(_identityId, objectId) { return objects.get(objectId) } },
      events: { async readVaultEvents() { return [{ ...tampered, identityId }] }, async readVaultObjects() { return [] } },
      segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
      verifier: signer,
    })
    await expect(reader.readAll()).rejects.toThrow('signature')
  })
})
