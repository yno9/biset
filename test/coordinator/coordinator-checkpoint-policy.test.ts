import { describe, expect, test } from 'bun:test'
import { deliverySeq } from '../../src/protocol/ids.ts'
import { coordinatorStreamCheckpointIsBehind } from '../../src/vault/coordinator-sync.ts'

describe('Coordinator stream checkpoint policy', () => {
  test('refreshes a missing or stale checkpoint even after the immediate outbox flush consumed every row', () => {
    expect(coordinatorStreamCheckpointIsBehind(undefined, deliverySeq(3n))).toBeTrue()
    expect(coordinatorStreamCheckpointIsBehind(deliverySeq(0n), deliverySeq(3n))).toBeTrue()
    expect(coordinatorStreamCheckpointIsBehind(deliverySeq(3n), deliverySeq(3n))).toBeFalse()
  })
})
