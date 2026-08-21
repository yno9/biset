import { describe, expect, test } from 'bun:test'
import { restoreRequestSigningBytes } from '../../src/protocol/signing.ts'
import type { RestoreRequestV1 } from '../../src/protocol/vault.ts'
import { requestRestoreForGap } from '../../src/vault/restore-workflow.ts'
import type { VaultRestoreRequestStateRecord, VaultRestoreRequestStateStore } from '../../src/vault/store.ts'

const identityId = 'did:web:alice.example'
const deviceId = 'device-c'
const gap = { kind: 'restoreRequired' as const, requestedCursor: '3', retainedFrom: '9', latestSeq: '12', reason: 'ttl-expired' as const }

class MemoryRestoreStateStore implements VaultRestoreRequestStateStore {
  value?: VaultRestoreRequestStateRecord
  async readRestoreRequestState() { return this.value && copy(this.value) }
  async writeRestoreRequestState(value: VaultRestoreRequestStateRecord) { this.value = copy(value) }
  async noteRestoreRequestAttempt(_identityId: string, _deviceId: string, attemptedAt: string) {
    if (!this.value) throw new Error('missing restore state')
    this.value = { ...this.value, attempts: this.value.attempts + 1, lastAttemptAt: attemptedAt }
  }
  async markRestoreRequestSubmitted(_identityId: string, _deviceId: string, submittedAt: string) {
    if (!this.value) throw new Error('missing restore state')
    this.value = { ...this.value, status: 'submitted', submittedAt }
  }
  async clearRestoreRequestState() { this.value = undefined }
}

const signer = {
  deviceId,
  async sign(bytes: Uint8Array) { return new Uint8Array([bytes.length]) },
}

describe('restore workflow', () => {
  test('durably records a signed gap request before network submission', async () => {
    const store = new MemoryRestoreStateStore()
    const sent: RestoreRequestV1[] = []
    const result = await requestRestoreForGap(store, { async request(value) { sent.push(value) } }, signer, identityId, gap, {
      now: () => new Date('2026-08-21T00:00:00.000Z'), newRequestId: () => 'restore-1', knownManifestRoot: 'root-c',
    })
    expect(result).toMatchObject({ kind: 'submitted', reused: false, request: { requestId: 'restore-1', reason: 'ttl-expired', knownManifestRoot: 'root-c' } })
    expect(store.value).toMatchObject({ status: 'submitted', attempts: 0, gap })
    expect(sent).toHaveLength(1)
    const { signature, ...unsigned } = sent[0]!
    expect(signature).toEqual(new Uint8Array([restoreRequestSigningBytes(unsigned).length]))
  })

  test('retries an uncertain submission with the same durable request ID', async () => {
    const store = new MemoryRestoreStateStore()
    let calls = 0
    const fail = { async request() { calls += 1; throw new Error('offline') } }
    const first = await requestRestoreForGap(store, fail, signer, identityId, gap, { now: () => new Date('2026-08-21T00:00:00.000Z'), newRequestId: () => 'restore-1' })
    expect(first).toMatchObject({ kind: 'pending', reused: false, request: { requestId: 'restore-1' } })
    expect(store.value).toMatchObject({ status: 'pending', attempts: 1 })
    const second = await requestRestoreForGap(store, { async request() { calls += 1 } }, signer, identityId, gap, { now: () => new Date('2026-08-21T00:01:00.000Z'), newRequestId: () => 'must-not-be-used' })
    expect(second).toMatchObject({ kind: 'submitted', reused: true, request: { requestId: 'restore-1' } })
    expect(store.value).toMatchObject({ status: 'submitted', attempts: 1 })
    expect(calls).toBe(2)
  })

  test('does not resubmit a still-active request after an app restart', async () => {
    const store = new MemoryRestoreStateStore()
    await requestRestoreForGap(store, { async request() {} }, signer, identityId, gap, { now: () => new Date('2026-08-21T00:00:00.000Z'), newRequestId: () => 'restore-1' })
    let calls = 0
    const result = await requestRestoreForGap(store, { async request() { calls += 1 } }, signer, identityId, gap, { now: () => new Date('2026-08-21T00:01:00.000Z') })
    expect(result).toMatchObject({ kind: 'submitted', reused: true, request: { requestId: 'restore-1' } })
    expect(calls).toBe(0)
  })
})

function copy(value: VaultRestoreRequestStateRecord): VaultRestoreRequestStateRecord {
  return { ...value, request: { ...value.request, signature: value.request.signature.slice() }, gap: { ...value.gap } }
}
