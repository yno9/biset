import { describe, expect, test } from 'bun:test'
import { decryptVaultObject } from '../../src/client/store/vault/objects.ts'
import { createJmapExport, decodeJmapExport, encodeJmapExport, eventStateRank, IMPORTED_KEYWORD, importJmapExport, JMAP_STATE_RANK, mergeJmapExports, type JmapExportV1 } from '../../src/client/store/vault/jmap-export.ts'
import { bytesToBase64url, equalBytes } from '../../src/protocol/canonical.ts'
import type { VaultEventAuthor } from '../../src/client/store/vault/events.ts'
import type { VaultEventV1 } from '../../src/protocol/vault.ts'
import { contactCardId, DIDCOMM_CONTACT_PROPERTY, type LocalJmapContactCard } from '../../src/client/store/projection/contacts.ts'

const base = { id: 'e1', threadId: 't1', receivedAt: '2026-01-01T00:00:00.000Z', mailboxIds: { inbox: true as const }, keywords: {} }
function file(at: string, rank: string, keywords: Record<string, true>): JmapExportV1 { return { version: 1, kind: 'biset.jmap-export', identityId: 'did:example:alice', exportedAt: at, mailboxes: [], blobs: {}, emails: [{ ...base, keywords, [JMAP_STATE_RANK]: { keywords: rank, mailboxIds: rank, content: rank } }] } }

describe('JMAP history export merge', () => {
  test('state rank lexical order matches actorSeq numeric order across digit widths', () => {
    const common = { createdAt: '2026-01-01T00:00:00.000Z', actorDeviceId: 'device', id: 'event' }
    expect(eventStateRank({ ...common, actorSeq: 9 }) < eventStateRank({ ...common, actorSeq: 10 })).toBe(true)
  })
  test('three partial exports converge in all six import orders', () => {
    const a = file('2026-01-01T00:00:00.000Z', '1', {})
    const b = file('2026-01-02T00:00:00.000Z', '2', { '$seen': true })
    const c = file('2026-01-03T00:00:00.000Z', '3', { '$flagged': true })
    const orders = [[a,b,c],[a,c,b],[b,a,c],[b,c,a],[c,a,b],[c,b,a]]
    const results = orders.map(values => mergeJmapExports(values).emails)
    for (const result of results) expect(result).toEqual(results[0])
    expect(results[0]![0]!.keywords).toEqual({ '$flagged': true })
  })
  test('extension-free exports use exportedAt and overlapping partial files form a complete union', () => {
    const old = file('2026-01-01T00:00:00.000Z', 'ignored', {}); delete old.emails[0]![JMAP_STATE_RANK]
    const recent = file('2026-01-02T00:00:00.000Z', 'ignored', { '$seen': true }); delete recent.emails[0]![JMAP_STATE_RANK]
    recent.emails.push({ ...base, id: 'e2', threadId: 't2', keywords: {} })
    expect(mergeJmapExports([recent, old])).toEqual(mergeJmapExports([old, recent]))
    expect(mergeJmapExports([old, recent]).emails.map(email => email.id)).toEqual(['e1', 'e2'])
    expect(mergeJmapExports([old, recent]).emails[0]!.keywords).toEqual({ '$seen': true })
  })
  test('merging the same export repeatedly is idempotent', () => {
    const value = file('2026-01-01T00:00:00.000Z', 'rank', { '$seen': true })
    expect(mergeJmapExports([value, value])).toEqual(mergeJmapExports([value]))
  })
  test('exports canonical JMAP plus blobs without key material', async () => {
    const exported = await createJmapExport({ identityId: 'did:example:alice', snapshot: { state: 's', mailboxes: [], emails: [base], contactCards: [] }, events: [], exportedAt: '2026-01-01T00:00:00.000Z', async download() { return new Uint8Array() } })
    const decoded = decodeJmapExport(encodeJmapExport(exported))
    expect(decoded.identityId).toBe('did:example:alice')
    expect(JSON.stringify(decoded)).not.toContain('segmentKey')
  })
  test('rejects an export for another identity before importing records', async () => {
    await expect(importJmapExport(file('2026-01-01T00:00:00.000Z', '1', {}), { identityId: 'did:example:bob' } as never)).rejects.toThrow('identity')
  })
  test('imports mail as signed R3 records and preserves the source rank timestamp', async () => {
    const identityId = 'did:example:alice'; const createdAt = '2025-04-03T02:01:00.000Z'
    const exported = file('2026-01-01T00:00:00.000Z', `${createdAt}|old-device|00000000000000000001|old-event`, {})
    exported.blobs.raw = bytesToBase64url(new TextEncoder().encode('Subject: hi\r\n\r\nbody'))
    exported.emails[0]!.blobId = 'raw'
    const signer: VaultEventAuthor = { deviceId: 'device-a', async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) }, async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) } }
    let committed: unknown; let seq = 0
    const result = await importJmapExport(exported, {
      identityId, actorDeviceId: 'device-a', snapshot: { state: '', mailboxes: [], emails: [], contactCards: [] }, events: [], signer,
      nextActorSeq: async () => ++seq, initialParents: async () => [],
      activeSegment: async () => ({ segmentId: 'segment-a', segmentKey: new Uint8Array(32).fill(4) }),
      async commit(records) { committed = records; return { addedEventIds: records.events.map(event => event.id), addedObjectIds: records.objects.map(object => object.objectId), addedKeyWraps: 0, targetIds: ['e1'] } },
    })
    expect(result.added).toBe(1)
    expect(result.events[0]!.createdAt).toBe(createdAt)
    expect((committed as { segmentKeys: unknown[] }).segmentKeys).toEqual([])
    // A file is editable plain JSON: what it adds is marked as imported.
    const metadata = JSON.parse(new TextDecoder().decode(await decryptVaultObject(new Uint8Array(32).fill(4), (committed as { objects: Parameters<typeof decryptVaultObject>[1][] }).objects[0]!)))
    expect(JSON.stringify(metadata)).toContain(IMPORTED_KEYWORD)
    expect((committed as { events: unknown[] }).events).toHaveLength(1)
    let secondCommit = false
    const currentEmail = { ...exported.emails[0]!, keywords: { '$flagged': true as const } }
    const newer = { ...result.events[0]!, id: 'newer-event', kind: 'keyword.set' as const, createdAt: '2026-08-01T00:00:00.000Z' }
    const oldResult = await importJmapExport(exported, { identityId, actorDeviceId: 'device-a', snapshot: { state: '', mailboxes: [], emails: [currentEmail], contactCards: [] }, events: [newer], signer, nextActorSeq: async () => ++seq, initialParents: async () => [], activeSegment: async () => ({ segmentId: 'segment-a', segmentKey: new Uint8Array(32).fill(4) }), async commit() { secondCommit = true; return { addedEventIds: [], targetIds: [] } } })
    expect(oldResult.skipped).toBe(1)
    expect(secondCommit).toBe(false)
  })

  describe('contacts (RFC 9610 ContactCard)', () => {
    const identityId = 'did:example:alice'
    const uid = 'urn:uuid:bob'; const id = contactCardId(uid)
    const card = (extra: Record<string, unknown> = {}) => ({ id, '@type': 'Card' as const, version: '1.0', uid, addressBookIds: { default: true as const }, name: { full: 'Bob' }, ...extra }) as LocalJmapContactCard
    const signer: VaultEventAuthor = { deviceId: 'device-a', async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) }, async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) } }
    const key = new Uint8Array(32).fill(4)
    async function importInto(exported: JmapExportV1, contactCards: LocalJmapContactCard[], events: VaultEventV1[] = []) {
      let seq = 0; const committed: VaultEventV1[] = []; const objects: Parameters<typeof decryptVaultObject>[1][] = []
      const result = await importJmapExport(exported, {
        identityId, actorDeviceId: 'device-a', snapshot: { state: '', mailboxes: [], emails: [], contactCards }, events, signer,
        nextActorSeq: async () => ++seq, initialParents: async () => [], activeSegment: async () => ({ segmentId: 'segment-a', segmentKey: key }),
        async commit(records) { committed.push(...records.events); objects.push(...records.objects); return { addedEventIds: [], targetIds: [] } },
      })
      const payloads = await Promise.all(objects.map(async object => JSON.parse(new TextDecoder().decode(await decryptVaultObject(key, object))).payload))
      return { result, committed, payloads }
    }
    const routed = card({ [DIDCOMM_CONTACT_PROPERTY]: { rotations: { 'did:peer:2.P': { prior: 'did:webvh:x:bob.example', iat: 1 } } } })

    test('a card is exported with its state rank, and the file round-trips', async () => {
      const event = { version: 1, id: 'ev', identityId, actorDeviceId: 'device-b', actorSeq: 7, kind: 'contact.set', targetIds: [`contact:${id}`], objectRefs: ['o'], parents: [], createdAt: '2026-05-01T00:00:00.000Z', signature: new Uint8Array([1]) } as VaultEventV1
      const exported = await createJmapExport({ identityId, snapshot: { state: 's', mailboxes: [], emails: [], contactCards: [routed] }, events: [event], exportedAt: '2026-06-01T00:00:00.000Z', async download() { return new Uint8Array() } })
      expect(exported.contactCards).toEqual([routed])
      expect(exported.addressBooks?.[0]?.id).toBe('default')
      expect(exported.contactCardStateRanks).toEqual({ [id]: eventStateRank(event) })
      expect(decodeJmapExport(encodeJmapExport(exported))).toEqual(exported)
    })

    test('importing adds a missing card, without its DIDComm routing state, dated at its rank', async () => {
      const rank = '2026-05-01T00:00:00.000Z|device-b|00000000000000000007|ev'
      const exported: JmapExportV1 = { ...file('2026-06-01T00:00:00.000Z', '1', {}), emails: [], contactCards: [routed], contactCardStateRanks: { [id]: rank } }
      const { result, committed, payloads } = await importInto(exported, [])
      expect(result.contactsAdded).toBe(1)
      expect(committed[0]).toMatchObject({ kind: 'contact.set', targetIds: [`contact:${id}`], createdAt: '2026-05-01T00:00:00.000Z' })
      expect(JSON.stringify(payloads[0])).not.toContain(DIDCOMM_CONTACT_PROPERTY)
      expect(payloads[0].patch['name']).toEqual({ full: 'Bob' })
    })

    test('a newer file updates only what differs, and never clears the local routing state; an older file changes nothing', async () => {
      const local = card({ name: { full: 'Robert' }, notes: { n1: { note: 'x' } }, [DIDCOMM_CONTACT_PROPERTY]: { confirmed: { 'did:peer:2.Y': true } } })
      const newer: JmapExportV1 = { ...file('2026-06-01T00:00:00.000Z', '1', {}), emails: [], contactCards: [card()], contactCardStateRanks: { [id]: '2026-05-02T00:00:00.000Z|d|00000000000000000001|e' } }
      const { result, payloads } = await importInto(newer, [local], [])
      expect(result.contactsUpdated).toBe(1)
      expect(payloads[0].patch).toEqual({ name: { full: 'Bob' }, notes: null })
      const localEvent = { version: 1, id: 'z', identityId, actorDeviceId: 'd', actorSeq: 1, kind: 'contact.set', targetIds: [`contact:${id}`], objectRefs: ['o'], parents: [], createdAt: '2026-07-01T00:00:00.000Z', signature: new Uint8Array([1]) } as VaultEventV1
      const older = await importInto(newer, [local], [localEvent])
      expect(older.committed).toEqual([])
      expect(older.result.skipped).toBe(1)
    })

    test('merging files keeps the card with the higher rank', () => {
      const a: JmapExportV1 = { ...file('2026-01-01T00:00:00.000Z', '1', {}), contactCards: [card({ name: { full: 'Old' } })], contactCardStateRanks: { [id]: '1' } }
      const b: JmapExportV1 = { ...file('2026-01-02T00:00:00.000Z', '1', {}), contactCards: [card({ name: { full: 'New' } })], contactCardStateRanks: { [id]: '2' } }
      expect(mergeJmapExports([a, b]).contactCards?.[0]?.name).toEqual({ full: 'New' })
      expect(mergeJmapExports([b, a])).toEqual(mergeJmapExports([a, b]))
    })
  })
})
