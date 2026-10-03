// Regression for the segment-validation gap found while unifying vault
// commit assembly (PLAN-simplify S3 stage 2, 2026-09-05): the local JMAP
// write path once accepted an empty segmentId or a SegmentKey that was not
// 32 bytes and encrypted under it.
import { describe, expect, test } from 'bun:test'
import { VaultBackedLocalJmapMutationSink } from '../src/client/store/projection/vault-mutation-sink.ts'
import type { ActiveVaultSegment } from '../src/client/store/vault/active-segment.ts'

const identityId = 'did:webvh:test:alice.example'
const segmentId = 'segment-1'

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
    const sink = sinkWith({ segmentId, segmentKey: new Uint8Array(31) })
    await expect(sink.commitIntents([], snapshot)).rejects.toThrow('active vault segment is invalid')
  })

  test('rejects a segment with an empty segmentId', async () => {
    const sink = sinkWith({ segmentId: '', segmentKey: new Uint8Array(32) })
    await expect(sink.commitIntents([], snapshot)).rejects.toThrow('active vault segment is invalid')
  })
})
