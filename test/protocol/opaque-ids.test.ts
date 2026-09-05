// PLAN.md §2.1's "opaque ID の grammar、最大長、生成規則を ids.ts と
// validator に固定する". Two tiers on purpose: a general bound
// (assertOpaqueId) wired into protocol/validate.ts for every free-form
// opaque ID (identity/device/ingress/checkpoint/request/manifest-root),
// loose enough that a human-readable test fixture like 'device-a' still
// passes -- and a strict grammar (assertVaultEventId/assertVaultObjectId/
// assertSegmentId) for the three ID types nothing but this codebase's own
// domainHash()/crypto.randomUUID() calls ever produces, proven against the
// REAL functions that mint them below rather than just declared.
import { describe, expect, test } from 'bun:test'
import { assertOpaqueId, assertSegmentId, assertVaultEventId, assertVaultObjectId } from '../../src/shared/protocol/ids.ts'
import { createVaultEvent, type VaultEventSigner } from '../../src/client/store/vault/events.ts'
import { createSegmentKey, encryptVaultObject } from '../../src/client/store/vault/objects.ts'
import { ActiveVaultSegmentManager } from '../../src/client/store/vault/active-segment.ts'
import { assertIngressEnvelope, assertVaultDeliveryAppend, ProtocolValidationError } from '../../src/shared/protocol/validate.ts'
import { sha256Bytes } from '../../src/shared/protocol/canonical.ts'
import type { ActiveVaultSegmentStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultSegmentRecord } from '../../src/client/store/vault/store.ts'
import type { SegmentKeyWrapV1 } from '../../src/shared/protocol/vault.ts'
import type { VaultEpochKeyResolver } from '../../src/client/store/vault/segment-key-resolver.ts'

const signer: VaultEventSigner = { deviceId: 'device-a', async sign() { return new Uint8Array([7]) }, async verify() { return true } }

describe('assertOpaqueId (general bound)', () => {
  test('accepts realistic DID-, UUID-, and hash-shaped values', () => {
    for (const value of ['did:web:alice.example', 'did:webvh:z6Mk...#device-1', crypto.randomUUID(), 'sha256:' + 'A'.repeat(43), 'device-a']) {
      expect(() => assertOpaqueId(value, 'id')).not.toThrow()
    }
  })

  test('rejects empty, over-length, and whitespace/control-character values', () => {
    expect(() => assertOpaqueId('', 'id')).toThrow('non-empty')
    expect(() => assertOpaqueId('a'.repeat(513), 'id')).toThrow('at most 512')
    expect(() => assertOpaqueId('has a space', 'id')).toThrow()
    expect(() => assertOpaqueId('has\ttab', 'id')).toThrow()
    expect(() => assertOpaqueId('has\nnewline', 'id')).toThrow()
    expect(() => assertOpaqueId('has\x00null', 'id')).toThrow()
    expect(() => assertOpaqueId(42, 'id')).toThrow()
  })

  test('is wired into protocol/validate.ts, not just declared in ids.ts', () => {
    const base = {
      version: 1 as const, ingressId: 'ingress-1', protocol: 'mail' as const, recipientIdentityId: 'did:web:alice.example',
      recipientDeviceSnapshot: ['device-a'], createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z',
      transportMetadata: {}, sourceEvidence: new Uint8Array([1]), protectedPayload: new Uint8Array([2]), protectedPayloadHash: sha256Bytes(new Uint8Array([2])),
    }
    expect(() => assertIngressEnvelope(base)).not.toThrow()
    expect(() => assertIngressEnvelope({ ...base, ingressId: 'has a space' })).toThrow(ProtocolValidationError)
    expect(() => assertIngressEnvelope({ ...base, recipientDeviceSnapshot: ['ok', 'bad id'] })).toThrow(ProtocolValidationError)

    const append = {
      version: 1 as const, identityId: 'did:web:alice.example', appendId: 'append-1', payload: new Uint8Array([1]),
      payloadHash: sha256Bytes(new Uint8Array([1])), senderDeviceId: 'device-a', sentAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([9]),
    }
    expect(() => assertVaultDeliveryAppend(append)).not.toThrow()
    expect(() => assertVaultDeliveryAppend({ ...append, senderDeviceId: 'x'.repeat(600) })).toThrow(ProtocolValidationError)
  })
})

describe('strict production-shape ID grammars', () => {
  test('assertVaultEventId/assertVaultObjectId accept real domainHash output and reject anything else', async () => {
    const object = await encryptVaultObject(createSegmentKey(), { segmentId: crypto.randomUUID(), plaintext: new Uint8Array([1, 2, 3]), aad: new Uint8Array([9]) })
    expect(() => assertVaultObjectId(object.objectId)).not.toThrow()

    const event = await createVaultEvent({
      identityId: 'did:web:alice.example', actorDeviceId: 'device-a', actorSeq: 1, kind: 'message.add',
      targetIds: ['msg-1'], objectRefs: [object.objectId], parents: [], createdAt: '2026-08-21T00:00:00.000Z',
    }, signer)
    expect(() => assertVaultEventId(event.id)).not.toThrow()

    for (const bad of ['event-1', 'sha256:tooshort', object.objectId.toUpperCase(), `md5:${'a'.repeat(43)}`]) {
      expect(() => assertVaultEventId(bad)).toThrow('sha256:')
      expect(() => assertVaultObjectId(bad)).toThrow('sha256:')
    }
  })

  test('assertSegmentId accepts a real ActiveVaultSegmentManager-minted ID and rejects a hand-picked one', async () => {
    const wraps: SegmentKeyWrapReader & SegmentKeyWrapWriter = (() => {
      const rows = new Map<string, SegmentKeyWrapV1>()
      const key = (id: string, segmentId: string, epoch: string) => `${id} ${segmentId} ${epoch}`
      return {
        async readSegmentKeyWrap(id, segmentId, epoch) { return rows.get(key(id, segmentId, epoch)) },
        async writeSegmentKeyWrap(wrap) { rows.set(key(wrap.identityId, wrap.segmentId, wrap.recipientEpoch), wrap) },
      }
    })()
    const segments: ActiveVaultSegmentStore = (() => {
      const rows: VaultSegmentRecord[] = []
      return {
        async currentSegment(id) { return rows.find(r => r.identityId === id && !r.sealed) },
        async allSegments(id) { return rows.filter(r => r.identityId === id) },
        async sealAndActivateSegment(next) {
          for (const row of rows) if (row.identityId === next.identityId && !row.sealed) row.sealed = true
          rows.push({ ...next })
        },
        async recordSegmentRewrapped(id, segmentId, epoch) {
          const row = rows.find(r => r.identityId === id && r.segmentId === segmentId)
          if (!row) throw new Error('no such segment')
          row.epoch = epoch
        },
      }
    })()
    const epochs: VaultEpochKeyResolver = {
      async currentVaultEpoch() { return { selfGroupId: 'self-group-a', epoch: '1' } },
      async deriveVaultEpochKey() { return createSegmentKey() },
    }
    const manager = new ActiveVaultSegmentManager({ identityId: 'did:web:alice.example', segments, wraps, epochs, signer })
    const segment = await manager.activeSegment()

    expect(() => assertSegmentId(segment.segmentId)).not.toThrow()
    expect(() => assertSegmentId('segment-1')).toThrow('UUID')
    expect(() => assertSegmentId(segment.segmentId.toUpperCase())).toThrow('UUID')
  })
})
