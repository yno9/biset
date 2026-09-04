// Regression for the segment-validation gap found while unifying vault
// commit assembly (PLAN-simplify S3 stage 2, 2026-09-05): every other
// commit path called assertActiveVaultSegment (4 conditions), but the
// local JMAP write path -- the most heavily used one -- hand-rolled only
// the last two, so an empty segmentId or a SegmentKey that was not 32
// bytes was accepted and encrypted under.
import { describe, expect, test } from 'bun:test'
import { VaultBackedLocalJmapMutationSink } from '../src/local-jmap/vault-mutation-sink.ts'
import type { ActiveVaultSegment } from '../src/vault/active-segment.ts'
import type { SegmentKeyWrapV1 } from '../src/shared/protocol/vault.ts'

const identityId = 'did:webvh:test:alice.example'
const segmentId = 'segment-1'

function wrap(overrides: Partial<SegmentKeyWrapV1> = {}): SegmentKeyWrapV1 {
  return {
    version: 1, identityId, selfGroupId: 'group-1', segmentId,
    sourceEpoch: 0, recipientEpoch: 0, grantorDeviceId: `${identityId}#device-1`,
    grantedAt: '2026-09-05T00:00:00.000Z',
    ciphertext: new Uint8Array([1]), nonce: new Uint8Array([2]), signature: new Uint8Array([3]),
    ...overrides,
  } as SegmentKeyWrapV1
}

function sinkWith(segment: ActiveVaultSegment): VaultBackedLocalJmapMutationSink {
  return new VaultBackedLocalJmapMutationSink({
    accountId: 'account-1',
    identityId,
    actorDeviceId: `${identityId}#device-1`,
    nextActorSeq: async () => 1,
    initialParents: async () => [],
    activeSegment: async () => segment,
    signer: { deviceId: `${identityId}#device-1`, sign: async () => new Uint8Array([9]) } as never,
    committer: { commitLocalMutation: async () => 'committed' as const },
  })
}

// An empty intent list is enough: segment validation runs before any
// mutation is built, and a segment that passes validation fails later for
// an unrelated reason -- which is exactly why these assertions match on the
// validation message rather than merely on TypeError (the looser form
// passed even against the pre-fix code).
const snapshot = { state: '0', mailboxes: [], emails: [] } as never

describe('local JMAP mutation sink segment validation', () => {
  test('rejects a segment whose SegmentKey is not 32 bytes', async () => {
    const sink = sinkWith({ segmentId, segmentKey: new Uint8Array(31), keyWraps: [wrap()] })
    await expect(sink.commitIntents([], snapshot)).rejects.toThrow('active vault segment does not match mutation identity')
  })

  test('rejects a segment with an empty segmentId', async () => {
    const sink = sinkWith({ segmentId: '', segmentKey: new Uint8Array(32), keyWraps: [wrap({ segmentId: '' })] })
    await expect(sink.commitIntents([], snapshot)).rejects.toThrow('active vault segment does not match mutation identity')
  })

  test('still rejects a missing key wrap', async () => {
    const sink = sinkWith({ segmentId, segmentKey: new Uint8Array(32), keyWraps: [] })
    await expect(sink.commitIntents([], snapshot)).rejects.toThrow('active vault segment does not match mutation identity')
  })

  test('still rejects a wrap belonging to another identity', async () => {
    const sink = sinkWith({ segmentId, segmentKey: new Uint8Array(32), keyWraps: [wrap({ identityId: 'did:webvh:test:mallory.example' })] })
    await expect(sink.commitIntents([], snapshot)).rejects.toThrow('active vault segment does not match mutation identity')
  })
})
