import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../src/protocol/didcomm/peer.ts'
import { createVaultEvent, type VaultEventAuthor } from '../src/client/store/vault/events.ts'
import { createSegmentKey, decryptVaultObject, encryptVaultObject } from '../src/client/store/vault/objects.ts'
import { canonicalBytes } from '../src/protocol/canonical.ts'
import {
  buildContactKeyRecord,
  contactKeyAad,
  type ContactKeyRef,
  decodeContactKey,
  type ContactKeyV1,
} from '../src/client/store/vault/contact-key.ts'
import { ContactKeyReader } from '../src/client/store/vault/contact-key-reader.ts'
import { decryptVaultMutationRecords } from '../src/client/store/vault/mutation-records.ts'
import { ContactKeyVaultSink } from '../src/client/store/vault/contact-key-sink.ts'

const identityId = 'did:webvh:alice.example'
const counterpartyDid = 'did:webvh:bob.example'
const segmentId = 'segment-1'
const segmentKey = createSegmentKey()
const signer: VaultEventAuthor = { deviceId: 'device-a' }

describe('contact key vault record', () => {
  test('encrypts canonical relationship keys and binds them to the counterparty and own kid', async () => {
    const value = contactKey('2026-08-27T00:00:00.000Z')
    const record = await buildContactKeyRecord(value, context(1), signer)

    expect(record.event.kind).toBe('contact-key.set')
    expect(record.event.targetIds).toEqual([`contact-key:${counterpartyDid}:${value.ownRelationshipKid}:${value.counterpartyRelationshipKid}`])
    const plaintext = await decryptVaultObject(segmentKey, record.object)
    expect(decodeContactKey(plaintext)).toMatchObject({
      counterpartyDid,
      ownRelationshipKid: value.ownRelationshipKid,
      counterpartyRelationshipKid: value.counterpartyRelationshipKid,
    })
    expect(record.object.aad).toEqual(contactKeyAad(identityId, segmentId, counterpartyDid, value))
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
    const currentValue = contactKey('2026-08-27T01:00:00.000Z', { ownRelationshipKid: old.contactKey.ownRelationshipKid, counterpartyRelationshipKid: old.contactKey.counterpartyRelationshipKid })
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

  test('a counterparty kid that was moved away from is no longer that counterparty', async () => {
    // The counterparty moved to a new did:peer (it removed a device, which
    // still holds the old key): the old kid must not speak for it any more.
    const old = await record(1, contactKey('2026-08-27T00:00:00.000Z'))
    const moved = await record(2, contactKey('2026-08-27T01:00:00.000Z', { ownRelationshipKid: old.contactKey.ownRelationshipKid, counterpartyRelationshipKid: old.contactKey.counterpartyRelationshipKid }))
    const reader = makeReader([old, moved])
    expect(await reader.currentForCounterpartyKid(old.contactKey.counterpartyRelationshipKid)).toBeNull()
    expect((await reader.currentForCounterpartyKid(moved.contactKey.counterpartyRelationshipKid))?.counterpartyDid).toBe(counterpartyDid)
    // History still knows the old kid; only acceptance stops.
    expect((await reader.forCounterpartyKid(old.contactKey.counterpartyRelationshipKid))?.counterpartyDid).toBe(counterpartyDid)
    expect(await reader.currentForCounterpartyKid('did:peer:2.unknown#key-1')).toBeNull()
  })

  test('a record in a format this version no longer reads is skipped, not fatal to the rest', async () => {
    // Written before ContactKeyV1 gained `seedId` (no backward compatibility
    // is kept): one such record used to stop every relationship from loading.
    const current = await record(1, contactKey('2026-08-27T00:00:00.000Z'))
    const legacy = await record(2, contactKey('2026-08-27T00:00:00.000Z'))
    const { seedId: _dropped, ...legacyShape } = legacy.contactKey
    const legacyObject = await encryptVaultObject(segmentKey, { segmentId, plaintext: canonicalBytes({ ...wireOf(legacyShape as ContactKeyV1) }), aad: legacy.object.aad })
    const { identityId: eventIdentity, actorDeviceId, actorSeq, kind, targetIds, parents, createdAt } = legacy.event
    const legacyEvent = await createVaultEvent({ identityId: eventIdentity, actorDeviceId, actorSeq, kind, targetIds, parents, createdAt, objectRefs: [legacyObject.objectId] }, signer)
    const reader = makeReader([current, { ...legacy, object: legacyObject, event: legacyEvent }])
    expect((await reader.readAll()).map(value => value.ownRelationshipKid)).toEqual([current.contactKey.ownRelationshipKid])
    // Nor does it stop a projection rebuild, which checks every record.
    const records = await decryptVaultMutationRecords(identityId, [{ ...legacyEvent, identityId }], [{ ...legacyObject, identityId }], { async resolveSegmentKey() { return segmentKey.slice() } })
    expect(records).toEqual([])
  })

  test('fails closed for independently introduced current generations', async () => {
    const first = await record(1, contactKey('2026-08-27T00:00:00.000Z'))
    const second = await record(2, contactKey('2026-08-27T01:00:00.000Z'))
    await expect(makeReader([first, second]).currentFor(counterpartyDid)).rejects.toThrow('ambiguous')
  })

  test('collapses the equivalent duplicate created by a crossing INIT/ACCEPT race', async () => {
    const first = await record(1, contactKey('2026-08-27T00:00:00.000Z'))
    const duplicate = await record(2, { ...first.contactKey, createdAt: '2026-08-27T00:00:01.000Z' })
    const reader = makeReader([first, duplicate])

    expect((await reader.currentFor(counterpartyDid))?.ownRelationshipKid).toBe(first.contactKey.ownRelationshipKid)
    expect((await reader.forOwnKid(first.contactKey.ownRelationshipKid))?.counterpartyRelationshipKid).toBe(first.contactKey.counterpartyRelationshipKid)
    expect((await reader.forCounterpartyKid(first.contactKey.counterpartyRelationshipKid))?.ownRelationshipKid).toBe(first.contactKey.ownRelationshipKid)
  })

  test('rejects a contact key event whose content no longer matches its id', async () => {
    const value = await record(1, contactKey('2026-08-27T00:00:00.000Z'))
    const tampered = { ...value, event: { ...value.event, actorSeq: 99 } }
    await expect(makeReader([tampered]).readAll()).rejects.toThrow('not intact')
  })
})

describe('contact key vault sink', () => {
  test('atomically queues the encrypted relationship credential without changing JMAP state', async () => {
    let committed: any
    const sink = new ContactKeyVaultSink({
      identityId,
      actorDeviceId: 'device-a',
      async nextActorSeq() { return 1 },
      async initialParents() { return [] },
      async activeSegment() { return { segmentId, segmentKey } },
      async currentSnapshot() { return { state: 'state-1', mailboxes: [], emails: [] } },
      signer,
      committer: { async commitLocalMutation(input) { committed = input; return 'committed' } },
    })

    const result = await sink.store(contactKey('2026-08-27T00:00:00.000Z'))
    expect(result.event.kind).toBe('contact-key.set')
    expect(committed.projection).toMatchObject({ state: 'state-1', emails: [] })
    expect(committed.events).toMatchObject([{ kind: 'contact-key.set' }])
  })
})

function contactKey(createdAt: string, supersedes?: ContactKeyRef): ContactKeyV1 {
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
    seedId: 'seed-1',
    ...(supersedes === undefined ? {} : { supersedes }),
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
        }))
      },
    },
    segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
  })
}

function wireOf(value: ContactKeyV1): Record<string, unknown> {
  const { ownX25519PrivateKey, ownEd25519PrivateKey, counterpartyPublicKey, ...rest } = value
  return { ...rest, ownX25519PrivateKey: toBase64url(ownX25519PrivateKey), ownEd25519PrivateKey: toBase64url(ownEd25519PrivateKey), counterpartyPublicKey: toBase64url(counterpartyPublicKey) }
}
