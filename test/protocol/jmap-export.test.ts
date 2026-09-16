import { describe, expect, test } from 'bun:test'
import { createJmapExport, decodeJmapExport, decryptJmapExport, encodeJmapExport, encryptJmapExport, eventStateRank, importJmapExport, JMAP_STATE_RANK, mergeJmapExports, type JmapExportV1 } from '../../src/client/store/vault/jmap-export.ts'
import { bytesToBase64url, equalBytes } from '../../src/protocol/canonical.ts'
import type { VaultEventSigner } from '../../src/client/store/vault/events.ts'

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
    const exported = await createJmapExport({ identityId: 'did:example:alice', snapshot: { state: 's', mailboxes: [], emails: [base] }, events: [], exportedAt: '2026-01-01T00:00:00.000Z', async download() { return new Uint8Array() } })
    const decoded = decodeJmapExport(encodeJmapExport(exported))
    expect(decoded.identityId).toBe('did:example:alice')
    expect(JSON.stringify(decoded)).not.toContain('keyWrap')
    const key = new Uint8Array(32).fill(7); const envelope = await encryptJmapExport(exported, '4', key)
    expect((await decryptJmapExport(envelope, key)).emails).toEqual(exported.emails)
  })
  test('rejects an export for another identity before importing records', async () => {
    await expect(importJmapExport(file('2026-01-01T00:00:00.000Z', '1', {}), { identityId: 'did:example:bob' } as never)).rejects.toThrow('identity')
  })
  test('imports mail as signed R3 records and preserves the source rank timestamp', async () => {
    const identityId = 'did:example:alice'; const createdAt = '2025-04-03T02:01:00.000Z'
    const exported = file('2026-01-01T00:00:00.000Z', `${createdAt}|old-device|00000000000000000001|old-event`, {})
    exported.blobs.raw = bytesToBase64url(new TextEncoder().encode('Subject: hi\r\n\r\nbody'))
    exported.emails[0]!.blobId = 'raw'
    const signer: VaultEventSigner = { deviceId: 'device-a', async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) }, async verify(deviceId, bytes, signature) { return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes)) } }
    let committed: unknown; let seq = 0
    const result = await importJmapExport(exported, {
      identityId, actorDeviceId: 'device-a', snapshot: { state: '', mailboxes: [], emails: [] }, events: [], signer,
      nextActorSeq: async () => ++seq, initialParents: async () => [],
      activeSegment: async () => ({ segmentId: 'segment-a', segmentKey: new Uint8Array(32).fill(4), keyWraps: [] }),
      async commit(records) { committed = records; return { addedEventIds: records.events.map(event => event.id), addedObjectIds: records.objects.map(object => object.objectId), addedKeyWraps: 0, targetIds: ['e1'] } },
    })
    expect(result.added).toBe(1)
    expect(result.events[0]!.createdAt).toBe(createdAt)
    expect((committed as { events: unknown[] }).events).toHaveLength(1)
    let secondCommit = false
    const currentEmail = { ...exported.emails[0]!, keywords: { '$flagged': true as const } }
    const newer = { ...result.events[0]!, id: 'newer-event', kind: 'keyword.set' as const, createdAt: '2026-08-01T00:00:00.000Z' }
    const oldResult = await importJmapExport(exported, { identityId, actorDeviceId: 'device-a', snapshot: { state: '', mailboxes: [], emails: [currentEmail] }, events: [newer], signer, nextActorSeq: async () => ++seq, initialParents: async () => [], activeSegment: async () => ({ segmentId: 'segment-a', segmentKey: new Uint8Array(32).fill(4), keyWraps: [] }), async commit() { secondCommit = true; return { addedEventIds: [], targetIds: [] } } })
    expect(oldResult.skipped).toBe(1)
    expect(secondCommit).toBe(false)
  })
})
