import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { IndexedDbVaultStore } from '../../src/client/store/vault/store.ts'
import { VaultProjector } from '../../src/client/store/vault/projector.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'
import { buildMailMessageAdd } from '../../src/client/store/vault/mail-message.ts'
import { buildVaultMutation } from '../../src/client/store/vault/mutations.ts'
import type { VaultEventSigner } from '../../src/client/store/vault/events.ts'

const identityId = 'did:example:alice'; const segmentId = 'segment-a'; const key = createSegmentKey()
const signer: VaultEventSigner = { deviceId: 'device-a', async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) }, async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) } }

afterEach(() => new Promise<void>(resolve => { const request = indexedDB.deleteDatabase('biset-vault-core'); request.onsuccess = request.onerror = request.onblocked = () => resolve() }))

describe('Vault projector arrival boundaries', () => {
  test('materializes after a late object and never resurrects a tombstoned email', async () => {
    const store = await IndexedDbVaultStore.open(); const projector = new VaultProjector(store, { async resolveSegmentKey() { return key.slice() } }, signer)
    const add = await buildMailMessageAdd({ email: { id: 'email-a', threadId: 'thread-a', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-01-01T00:00:00.000Z' }, rawRfc5322: new TextEncoder().encode('Subject: A\r\n\r\nbody') }, { identityId, actorDeviceId: 'device-a', actorSeq: 1, parents: [], segmentId, segmentKey: key, createdAt: '2026-01-01T00:00:00.000Z' }, signer)
    await store.commitIncomingRecords({ identityId, events: [{ ...add.event, identityId }], objects: [], keyWraps: [] })
    expect((await projector.rebuildAll(identityId)).emails).toEqual([])
    expect((await store.readProjectionMeta(identityId)).pending).toEqual(['email-a'])
    await store.commitIncomingRecords({ identityId, events: [], objects: [{ ...add.metadataObject, identityId }, { ...add.rawRfc5322Object, identityId }], keyWraps: [] })
    expect((await projector.recomputeEmails(identityId, ['email-a'])).emails.map(email => email.id)).toEqual(['email-a'])

    const tombstone = await buildVaultMutation({ kind: 'message.tombstone', targetIds: ['email-a'], payload: { emailId: 'email-a' } }, { identityId, actorDeviceId: 'device-a', actorSeq: 2, parents: [add.event.id], segmentId, segmentKey: key, createdAt: '2026-01-02T00:00:00.000Z' }, signer)
    await store.commitIncomingRecords({ identityId, events: [{ ...tombstone.event, identityId }], objects: [{ ...tombstone.object, identityId }], keyWraps: [] })
    expect((await projector.recomputeEmails(identityId, ['email-a'])).emails).toEqual([])
    const lateAdd = await buildMailMessageAdd({ email: { id: 'email-a', threadId: 'thread-a', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-01-03T00:00:00.000Z' }, rawRfc5322: new TextEncoder().encode('late') }, { identityId, actorDeviceId: 'device-a', actorSeq: 3, parents: [tombstone.event.id], segmentId, segmentKey: key, createdAt: '2026-01-03T00:00:00.000Z' }, signer)
    await store.commitIncomingRecords({ identityId, events: [{ ...lateAdd.event, identityId }], objects: [{ ...lateAdd.metadataObject, identityId }, { ...lateAdd.rawRfc5322Object, identityId }], keyWraps: [] })
    expect((await projector.recomputeEmails(identityId, ['email-a'])).emails).toEqual([])
    store.close()
  })
})
