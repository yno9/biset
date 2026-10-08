// The address book (PLAN-refactor.md §12): JMAP for Contacts (RFC 9610)
// cards, kept as `contact.set` PatchObjects in the Vault and folded by the
// reducer the same way on every device.
import { describe, expect, test } from 'bun:test'
import { canonicalBytes, equalBytes } from '../../src/protocol/canonical.ts'
import type { VaultEventV1 } from '../../src/protocol/vault.ts'
import { reduceLocalJmapProjection } from '../../src/client/store/projection/reducer.ts'
import {
  assertContactSetPayload, contactCardId, contactTargetId, creatingPatch, DIDCOMM_CONTACT_PROPERTY, didContactUid, type ContactSetPayload, type LocalJmapContactCard,
} from '../../src/client/store/projection/contacts.ts'
import { LocalJmapGateway, LocalJmapTransport, type LocalJmapReadModel, type LocalJmapSnapshot } from '../../src/client/store/projection/gateway.ts'
import { VaultBackedLocalJmapMutationSink } from '../../src/client/store/projection/vault-mutation-sink.ts'
import type { VaultEventAuthor } from '../../src/client/store/vault/events.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'

const IDENTITY = 'did:web:alice.example'
const BOB = 'did:webvh:QmScid:bob.example'
const bobUid = didContactUid(BOB)
const bobId = contactCardId(bobUid)

let sequence = 0
function record(payload: ContactSetPayload, at: string, device = 'device-a') {
  sequence += 1
  const targetIds = [contactTargetId(payload.cardId)]
  const event: VaultEventV1 = {
    version: 1, id: `event-${sequence}`, identityId: IDENTITY, actorDeviceId: device, actorSeq: sequence, kind: 'contact.set',
    targetIds, objectRefs: ['object'], parents: [], createdAt: at, signature: new Uint8Array([1]),
  }
  return { event, plaintext: canonicalBytes({ version: 1, kind: 'contact.set', targetIds, payload: payload as never }) }
}
const fold = (records: ReturnType<typeof record>[]) => reduceLocalJmapProjection(IDENTITY, { mailboxes: [], emails: [], contactCards: [] }, records).contactCards
const bobCard = (extra: Record<string, unknown> = {}) => creatingPatch({ '@type': 'Card', version: '1.0', uid: bobUid, onlineServices: { d1: { service: 'DIDComm', uri: BOB } }, ...extra } as never)

describe('contact ids', () => {
  test('a public DID\'s card uid is RFC 9562 name-based (v5, URL namespace), so every device makes the same card', () => {
    expect(bobUid).toBe('urn:uuid:26a9163a-ad74-586e-8597-abb16d5094fd')
    expect(contactCardId(bobUid)).toBe(bobId)
    expect(contactCardId('urn:uuid:other')).not.toBe(bobId)
  })
})

describe('contact.set in the reducer', () => {
  test('two devices creating the same card at once make one card', () => {
    const cards = fold([record({ cardId: bobId, patch: bobCard() }, '2026-10-08T00:00:00Z', 'a'), record({ cardId: bobId, patch: bobCard() }, '2026-10-08T00:00:00Z', 'b')])
    expect(cards).toHaveLength(1)
    expect(cards[0]).toMatchObject({ id: bobId, '@type': 'Card', version: '1.0', uid: bobUid, addressBookIds: { default: true } })
  })

  test('patches apply per path, last writer wins: different properties both survive, the same one takes the later', () => {
    const cards = fold([
      record({ cardId: bobId, patch: bobCard() }, '2026-10-08T00:00:00Z'),
      record({ cardId: bobId, patch: { name: { full: 'Bob' } } }, '2026-10-08T00:02:00Z', 'b'),
      record({ cardId: bobId, patch: { name: { full: 'Robert' } } }, '2026-10-08T00:01:00Z', 'a'),
      record({ cardId: bobId, patch: { 'emails/e1': { address: 'bob@example.com' } } }, '2026-10-08T00:01:30Z', 'a'),
    ])
    expect(cards[0]!.name).toEqual({ full: 'Bob' })
    expect(cards[0]!.emails).toEqual({ e1: { address: 'bob@example.com' } })
  })

  test('rotations recorded by two devices add up, and re-creating the card does not drop them', () => {
    const rotation = (did: string, iat: number) => ({ [`${DIDCOMM_CONTACT_PROPERTY}/rotations/${did}`]: { prior: BOB, iat } })
    const cards = fold([
      record({ cardId: bobId, patch: bobCard() }, '2026-10-08T00:00:00Z'),
      record({ cardId: bobId, patch: rotation('did:peer:2.P1', 1) }, '2026-10-08T00:01:00Z', 'a'),
      record({ cardId: bobId, patch: rotation('did:peer:2.P2', 2) }, '2026-10-08T00:01:00Z', 'b'),
      record({ cardId: bobId, patch: bobCard() }, '2026-10-08T00:02:00Z', 'c'),
    ])
    expect(Object.keys((cards[0]![DIDCOMM_CONTACT_PROPERTY] as { rotations: object }).rotations).sort()).toEqual(['did:peer:2.P1', 'did:peer:2.P2'])
  })

  test('after a destroy, only a creating patch brings the card back', () => {
    const destroyed = [record({ cardId: bobId, patch: bobCard() }, '2026-10-08T00:00:00Z'), record({ cardId: bobId, destroy: true }, '2026-10-08T00:01:00Z')]
    expect(fold([...destroyed, record({ cardId: bobId, patch: { name: { full: 'Bob' } } }, '2026-10-08T00:02:00Z')])).toEqual([])
    expect(fold([...destroyed, record({ cardId: bobId, patch: bobCard() }, '2026-10-08T00:02:00Z')])).toHaveLength(1)
  })

  test('refuses a payload that would change a card\'s id or uid, or names another target', () => {
    expect(() => assertContactSetPayload({ cardId: bobId, patch: { uid: 'urn:uuid:x' } }, contactTargetId(bobId))).toThrow('may not change')
    expect(() => assertContactSetPayload({ cardId: bobId, patch: { id: 'x' } }, contactTargetId(bobId))).toThrow('may not change')
    expect(() => assertContactSetPayload({ cardId: bobId, patch: { uid: bobUid } }, contactTargetId(bobId))).not.toThrow()
    expect(() => assertContactSetPayload({ cardId: bobId, destroy: true }, contactTargetId('other'))).toThrow('does not match')
  })

  test('contact cards are part of the projection state', () => {
    const empty = reduceLocalJmapProjection(IDENTITY, { mailboxes: [], emails: [], contactCards: [] }, [])
    const withCard = reduceLocalJmapProjection(IDENTITY, { mailboxes: [], emails: [], contactCards: [] }, [record({ cardId: bobId, patch: bobCard() }, '2026-10-08T00:00:00Z')])
    expect(withCard.state).not.toBe(empty.state)
  })
})

describe('JMAP for Contacts through the local gateway', () => {
  const signer: VaultEventAuthor = {
    deviceId: 'device-a',
    async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
    async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
  }

  function local() {
    let snapshot: LocalJmapSnapshot = { state: 'state-0', mailboxes: [], emails: [], contactCards: [] }
    let seq = 0
    const readModel: LocalJmapReadModel = { async snapshot() { return snapshot }, async download() { throw new Error('no blobs') } }
    const sink = new VaultBackedLocalJmapMutationSink({
      accountId: 'acct', identityId: IDENTITY, actorDeviceId: 'device-a',
      async nextActorSeq() { return ++seq }, async initialParents() { return [] },
      async activeSegment() { return { segmentId: 'segment-1', segmentKey: createSegmentKey() } },
      signer,
      committer: { async commitLocalMutation(input) { snapshot = input.projection; return 'committed' } },
      now: () => new Date('2026-10-08T00:00:00.000Z'),
    })
    const transport = new LocalJmapTransport(new LocalJmapGateway({ accountId: 'acct', identityId: IDENTITY, readModel, mutationSink: sink }))
    const call = async (name: string, args: Record<string, unknown>) => (await transport.call<{ methodResponses: Array<[string, Record<string, unknown>, string]> }>([{ name, arguments: { accountId: 'acct', ...args }, callId: 'c' }])).methodResponses[0]!
    return { transport, call }
  }

  test('the session advertises urn:ietf:params:jmap:contacts and the default address book', async () => {
    const { transport, call } = local()
    expect((await transport.session()).capabilities).toHaveProperty('urn:ietf:params:jmap:contacts')
    const [, books] = await call('AddressBook/get', {})
    expect(books.list).toEqual([expect.objectContaining({ id: 'default', isDefault: true })])
  })

  test('create, read, query, update and destroy a card', async () => {
    const { call } = local()
    const [, created] = await call('ContactCard/set', { create: { k1: { uid: 'urn:uuid:carol', name: { full: 'Carol' }, emails: { e1: { address: 'carol@example.com' } } } } })
    const id = contactCardId('urn:uuid:carol')
    expect(created.created).toEqual({ k1: { id, uid: 'urn:uuid:carol', addressBookIds: { default: true } } })
    const [, got] = await call('ContactCard/get', { ids: [id] })
    expect((got.list as LocalJmapContactCard[])[0]).toMatchObject({ '@type': 'Card', version: '1.0', name: { full: 'Carol' } })
    expect((await call('ContactCard/query', { filter: { inAddressBook: 'default' } }))[1].ids).toEqual([id])

    expect((await call('ContactCard/set', { create: { k2: { uid: 'urn:uuid:carol' } } }))[1].notCreated).toMatchObject({ k2: { type: 'alreadyExists' } })
    expect((await call('ContactCard/set', { update: { [id]: { 'name/full': 'Caroline' } } }))[1].updated).toEqual({ [id]: null })
    expect(((await call('ContactCard/get', { ids: [id] }))[1].list as LocalJmapContactCard[])[0]!.name).toEqual({ full: 'Caroline' })
    expect((await call('ContactCard/set', { update: { [id]: { 'nickNames/n1/name': 'C' } } }))[1].notUpdated).toMatchObject({ [id]: { type: 'invalidPatch' } })

    expect((await call('ContactCard/set', { destroy: [id] }))[1].destroyed).toEqual([id])
    expect((await call('ContactCard/get', { ids: [id] }))[1].notFound).toEqual([id])
  })

  test('a JMAP client may not write the DIDComm routing state', async () => {
    const { call } = local()
    expect((await call('ContactCard/set', { create: { k1: { uid: 'urn:uuid:x', [DIDCOMM_CONTACT_PROPERTY]: { rotations: {} } } } }))[1].notCreated).toMatchObject({ k1: { type: 'forbidden' } })
    await call('ContactCard/set', { create: { k1: { uid: 'urn:uuid:x' } } })
    const id = contactCardId('urn:uuid:x')
    expect((await call('ContactCard/set', { update: { [id]: { [`${DIDCOMM_CONTACT_PROPERTY}/rotations/did:peer:2.P`]: { prior: BOB, iat: 1 } } } }))[1].notUpdated).toMatchObject({ [id]: { type: 'forbidden' } })
  })
})
