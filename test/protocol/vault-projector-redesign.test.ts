import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { IndexedDbVaultStore } from '../../src/client/store/vault/store.ts'
import { VaultProjector } from '../../src/client/store/vault/projector.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'
import { buildMailMessageAdd } from '../../src/client/store/vault/mail-message.ts'
import { buildVaultMutation } from '../../src/client/store/vault/mutations.ts'
import type { VaultEventAuthor } from '../../src/client/store/vault/events.ts'
import { contactCardId, contactSetIntent, creatingPatch } from '../../src/client/store/projection/contacts.ts'

const identityId = 'did:example:alice'; const segmentId = 'segment-a'; const key = createSegmentKey()
const signer: VaultEventAuthor = { deviceId: 'device-a', async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) }, async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) } }

afterEach(() => new Promise<void>(resolve => { const request = indexedDB.deleteDatabase('biset-vault-core'); request.onsuccess = request.onerror = request.onblocked = () => resolve() }))

describe('Vault projector arrival boundaries', () => {
  test('materializes after a late object and never resurrects a tombstoned email', async () => {
    const store = await IndexedDbVaultStore.open(); const projector = new VaultProjector(store, { async resolveSegmentKey() { return key.slice() } }, signer)
    const add = await buildMailMessageAdd({ email: { id: 'email-a', threadId: 'thread-a', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-01-01T00:00:00.000Z' }, rawRfc5322: new TextEncoder().encode('Subject: A\r\n\r\nbody') }, { identityId, actorDeviceId: 'device-a', actorSeq: 1, parents: [], segmentId, segmentKey: key, createdAt: '2026-01-01T00:00:00.000Z' }, signer)
    await store.commitIncomingRecords({ identityId, events: [{ ...add.event, identityId }], objects: [], segmentKeys: [] })
    expect((await projector.rebuildAll(identityId)).emails).toEqual([])
    expect((await store.readProjectionMeta(identityId)).pending).toEqual(['email-a'])
    await store.commitIncomingRecords({ identityId, events: [], objects: [{ ...add.metadataObject, identityId }, { ...add.rawRfc5322Object, identityId }], segmentKeys: [] })
    expect((await projector.recomputeEmails(identityId, ['email-a'])).emails.map(email => email.id)).toEqual(['email-a'])

    const tombstone = await buildVaultMutation({ kind: 'message.tombstone', targetIds: ['email-a'], payload: { emailId: 'email-a' } }, { identityId, actorDeviceId: 'device-a', actorSeq: 2, parents: [add.event.id], segmentId, segmentKey: key, createdAt: '2026-01-02T00:00:00.000Z' }, signer)
    await store.commitIncomingRecords({ identityId, events: [{ ...tombstone.event, identityId }], objects: [{ ...tombstone.object, identityId }], segmentKeys: [] })
    expect((await projector.recomputeEmails(identityId, ['email-a'])).emails).toEqual([])
    const lateAdd = await buildMailMessageAdd({ email: { id: 'email-a', threadId: 'thread-a', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-01-03T00:00:00.000Z' }, rawRfc5322: new TextEncoder().encode('late') }, { identityId, actorDeviceId: 'device-a', actorSeq: 3, parents: [tombstone.event.id], segmentId, segmentKey: key, createdAt: '2026-01-03T00:00:00.000Z' }, signer)
    await store.commitIncomingRecords({ identityId, events: [{ ...lateAdd.event, identityId }], objects: [{ ...lateAdd.metadataObject, identityId }, { ...lateAdd.rawRfc5322Object, identityId }], segmentKeys: [] })
    expect((await projector.recomputeEmails(identityId, ['email-a'])).emails).toEqual([])
    store.close()
  })

  test('a contact card\'s events, targeted contact:<id>, update its card -- not an email -- on an incremental recompute', async () => {
    const store = await IndexedDbVaultStore.open(); const projector = new VaultProjector(store, { async resolveSegmentKey() { return key.slice() } }, signer)
    const cardId = contactCardId('urn:uuid:bob')
    const commit = async (intent: ReturnType<typeof contactSetIntent>, actorSeq: number) => {
      const built = await buildVaultMutation(intent, { identityId, actorDeviceId: 'device-a', actorSeq, parents: [], segmentId, segmentKey: key, createdAt: `2026-01-0${actorSeq}T00:00:00.000Z` }, signer)
      await store.commitIncomingRecords({ identityId, events: [{ ...built.event, identityId }], objects: [{ ...built.object, identityId }], segmentKeys: [] })
      return built.event.targetIds
    }
    await projector.rebuildAll(identityId)
    const targets = await commit(contactSetIntent({ cardId, patch: creatingPatch({ '@type': 'Card', version: '1.0', uid: 'urn:uuid:bob', name: { full: 'Bob' } }) }), 1)
    expect((await projector.recomputeEmails(identityId, targets)).contactCards.map(card => card.name)).toEqual([{ full: 'Bob' }])
    await commit(contactSetIntent({ cardId, destroy: true }), 2)
    const projection = await projector.recomputeEmails(identityId, targets)
    expect(projection.contactCards).toEqual([])
    expect(projection.emails).toEqual([])
    expect((await projector.rebuildAll(identityId)).state).toBe(projection.state)
    store.close()
  })
})
