import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../src/shared/protocol/canonical.ts'
import { generatePeerIdentity } from '../src/didcomm/peer.ts'
import { createSegmentKeyWrap } from '../src/vault/crypto.ts'
import { decodeVaultDeliveryPack } from '../src/vault/delivery-pack.ts'
import type { VaultEventSigner } from '../src/vault/events.ts'
import { createSegmentKey, decryptVaultObject } from '../src/vault/objects.ts'
import {
  buildContactKeyRecord,
  contactKeyAad,
  decodeContactKey,
  type ContactKeyV1,
} from '../src/vault/contact-key.ts'
import { ContactKeyReader } from '../src/vault/contact-key-reader.ts'
import { ContactKeyVaultSink } from '../src/vault/contact-key-sink.ts'

const identityId = 'did:webvh:alice.example'
const counterpartyDid = 'did:webvh:bob.example'
const segmentId = 'segment-1'
const segmentKey = createSegmentKey()
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) },
}

describe('contact key vault record', () => {
  test('encrypts canonical relationship keys and binds them to the counterparty and own kid', async () => {
    const value = contactKey('2026-08-27T00:00:00.000Z')
    const record = await buildContactKeyRecord(value, context(1), signer)

    expect(record.event.kind).toBe('contact-key.set')
    expect(record.event.targetIds).toEqual([`contact-key:${counterpartyDid}:${value.ownRelationshipKid}`])
    const plaintext = await decryptVaultObject(segmentKey, record.object)
    expect(decodeContactKey(plaintext)).toMatchObject({
      counterpartyDid,
      ownRelationshipKid: value.ownRelationshipKid,
      counterpartyRelationshipKid: value.counterpartyRelationshipKid,
    })
    expect(record.object.aad).toEqual(contactKeyAad(identityId, segmentId, counterpartyDid, value.ownRelationshipKid))
  })

  test('rejects own or counterparty key material that does not match its self-certifying did:peer kid', () => {
    const value = contactKey('2026-08-27T00:00:00.000Z')
    expect(() => decodeContactKey(encoded({ ...value, ownX25519PrivateKey: new Uint8Array(32).fill(9) }))).toThrow('own kid')
    expect(() => decodeContactKey(encoded({ ...value, counterpartyPublicKey: new Uint8Array(32).fill(9) }))).toThrow('counterparty kid')
  })
})

describe('contact key vault reader', () => {
  test('selects the unique unsuperseded generation and supports own-kid lookup', async () => {
    const old = await record(1, contactKey('2026-08-27T00:00:00.000Z'))
    const currentValue = contactKey('2026-08-27T01:00:00.000Z', old.contactKey.ownRelationshipKid)
    const current = await record(2, currentValue)
    const reader = makeReader([old, current])

    expect((await reader.forCounterparty(counterpartyDid)).map(value => value.ownRelationshipKid)).toEqual([
      old.contactKey.ownRelationshipKid,
      current.contactKey.ownRelationshipKid,
    ])
    expect((await reader.currentFor(counterpartyDid))?.ownRelationshipKid).toBe(current.contactKey.ownRelationshipKid)
    expect((await reader.forOwnKid(old.contactKey.ownRelationshipKid))?.counterpartyDid).toBe(counterpartyDid)
    expect(await reader.currentFor('did:webvh:nobody.example')).toBeNull()
    expect(await reader.forOwnKid('did:peer:2.unknown#key-1')).toBeNull()
  })

  test('fails closed for independently introduced current generations', async () => {
    const first = await record(1, contactKey('2026-08-27T00:00:00.000Z'))
    const second = await record(2, contactKey('2026-08-27T01:00:00.000Z'))
    await expect(makeReader([first, second]).currentFor(counterpartyDid)).rejects.toThrow('ambiguous')
  })

  test('rejects a contact key event whose signature is invalid', async () => {
    const value = await record(1, contactKey('2026-08-27T00:00:00.000Z'))
    const tampered = { ...value, event: { ...value.event, signature: new Uint8Array([0]) } }
    await expect(makeReader([tampered]).readAll()).rejects.toThrow('signature')
  })
})

describe('contact key vault sink', () => {
  test('atomically queues the encrypted relationship credential without changing JMAP state', async () => {
    const wrap = await createSegmentKeyWrap(
      new Uint8Array(32).fill(7),
      segmentKey,
      { identityId, selfGroupId: 'self-group-1', segmentId, sourceEpoch: '1', recipientEpoch: '1', grantorDeviceId: 'device-a', grantedAt: '2026-08-27T00:00:00.000Z' },
      signer,
    )
    let committed: any
    const sink = new ContactKeyVaultSink({
      identityId,
      actorDeviceId: 'device-a',
      async nextActorSeq() { return 1 },
      async initialParents() { return [] },
      async activeSegment() { return { segmentId, segmentKey, keyWraps: [wrap] } },
      async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } },
      signer,
      committer: { async commitLocalMutation(input) { committed = input; return 'committed' } },
    })

    const result = await sink.store(contactKey('2026-08-27T00:00:00.000Z'))
    expect(result.event.kind).toBe('contact-key.set')
    expect(committed.projection).toMatchObject({ state: 'state-1', emails: [] })
    const pack = decodeVaultDeliveryPack(committed.deliveryOutbox.payload)
    expect(pack.events).toMatchObject([{ kind: 'contact-key.set' }])
  })
})

function contactKey(createdAt: string, supersedesKid?: string): ContactKeyV1 {
  const mediator = generatePeerIdentity()
  const service = { uri: 'https://mediator.test.example', routingKeys: [mediator.xKid] }
  const own = generatePeerIdentity(service)
  const counterparty = generatePeerIdentity(service)
  return {
    version: 1,
    kind: 'contact-key',
    identityId,
    counterpartyDid,
    ownRelationshipKid: own.xKid,
    ownX25519PrivateKey: own.xPriv,
    ownEd25519PrivateKey: own.edPriv,
    counterpartyRelationshipKid: counterparty.xKid,
    counterpartyPublicKey: counterparty.xPub,
    createdAt,
    ...(supersedesKid === undefined ? {} : { supersedesKid }),
  }
}

function encoded(value: ContactKeyV1): Uint8Array {
  const wire = {
    ...value,
    ownX25519PrivateKey: toBase64url(value.ownX25519PrivateKey),
    ownEd25519PrivateKey: toBase64url(value.ownEd25519PrivateKey),
    counterpartyPublicKey: toBase64url(value.counterpartyPublicKey),
  }
  return new TextEncoder().encode(JSON.stringify(wire))
}

function toBase64url(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function context(actorSeq: number) {
  return { identityId, actorDeviceId: 'device-a', actorSeq, parents: actorSeq === 1 ? [] : ['event-1'], segmentId, segmentKey }
}

async function record(actorSeq: number, value: ContactKeyV1) {
  return buildContactKeyRecord(value, context(actorSeq), signer)
}

function makeReader(records: Awaited<ReturnType<typeof record>>[]): ContactKeyReader {
  const objects = new Map(records.map(value => [value.object.objectId, { ...value.object, identityId }]))
  return new ContactKeyReader({
    identityId,
    objects: { async readObject(_identityId, objectId) { return objects.get(objectId) } },
    events: {
      async readCredentialEvents() {
        return records.map(value => ({
          ...value.event,
          identityId,
          targetIds: [...value.event.targetIds],
          objectRefs: [...value.event.objectRefs],
          parents: [...value.event.parents],
          signature: value.event.signature.slice(),
        }))
      },
    },
    segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
    verifier: signer,
  })
}
