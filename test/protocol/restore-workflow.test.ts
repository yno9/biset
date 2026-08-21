import { describe, expect, test } from 'bun:test'
import { restoreRequestSigningBytes } from '../../src/protocol/signing.ts'
import type { RestoreRequestV1 } from '../../src/protocol/vault.ts'
import { pollRestoreOffers, pollRestoreRequests, requestRestoreForGap, submitRestoreOffer } from '../../src/vault/restore-workflow.ts'
import type { VaultRestoreOfferOutboxRecord, VaultRestoreOfferOutboxStore, VaultRestoreRequestStateRecord, VaultRestoreRequestStateStore } from '../../src/vault/store.ts'

const identityId = 'did:web:alice.example'
const deviceId = 'device-c'
const gap = { kind: 'restoreRequired' as const, requestedCursor: '3', retainedFrom: '9', latestSeq: '12', reason: 'ttl-expired' as const }

class MemoryRestoreStateStore implements VaultRestoreRequestStateStore, VaultRestoreOfferOutboxStore {
  value?: VaultRestoreRequestStateRecord
  offer?: VaultRestoreOfferOutboxRecord
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
  async readRestoreOfferOutbox() { return this.offer && copyOffer(this.offer) }
  async writeRestoreOfferOutbox(value: VaultRestoreOfferOutboxRecord) { this.offer = copyOffer(value) }
  async noteRestoreOfferAttempt(_identityId: string, _requestId: string, _responderDeviceId: string, attemptedAt: string) {
    if (!this.offer) throw new Error('missing restore offer')
    this.offer = { ...this.offer, attempts: this.offer.attempts + 1, lastAttemptAt: attemptedAt }
  }
  async markRestoreOfferSubmitted(_identityId: string, _requestId: string, _responderDeviceId: string, submittedAt: string) {
    if (!this.offer) throw new Error('missing restore offer')
    this.offer = { ...this.offer, status: 'submitted', submittedAt }
  }
  async clearRestoreOfferOutbox() { this.offer = undefined }
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

  test('signs polls and durably retries a user-approved peer offer', async () => {
    const store = new MemoryRestoreStateStore()
    const request = { version: 1 as const, requestId: 'restore-1', identityId, requesterDeviceId: deviceId, reason: 'ttl-expired' as const, requestedAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-21T00:15:00.000Z', signature: new Uint8Array([1]) }
    const responder = { deviceId: 'device-a', async sign(bytes: Uint8Array) { return new Uint8Array([bytes.length]) } }
    const seenPolls: string[] = []
    await pollRestoreRequests({ async pullRequests(value) { seenPolls.push(value.kind); return [request] } }, responder, identityId, () => new Date('2026-08-21T00:01:00.000Z'))
    await pollRestoreOffers({ async pullOffers(value) { seenPolls.push(value.kind); return [] } }, signer, identityId, () => new Date('2026-08-21T00:01:00.000Z'))
    expect(seenPolls).toEqual(['requests', 'offers'])

    const first = await submitRestoreOffer(store, { async offer() { throw new Error('offline') } }, responder, request, 'root-a', { now: () => new Date('2026-08-21T00:02:00.000Z') })
    expect(first).toMatchObject({ kind: 'pending', reused: false, offer: { responderDeviceId: 'device-a', expiresAt: '2026-08-21T00:12:00.000Z' } })
    expect(store.offer).toMatchObject({ status: 'pending', attempts: 1 })
    const second = await submitRestoreOffer(store, { async offer() {} }, responder, request, 'must-not-change', { now: () => new Date('2026-08-21T00:03:00.000Z') })
    expect(second).toMatchObject({ kind: 'submitted', reused: true, offer: { manifestRoot: 'root-a' } })
    expect(store.offer).toMatchObject({ status: 'submitted', attempts: 1 })
  })
})

function copy(value: VaultRestoreRequestStateRecord): VaultRestoreRequestStateRecord {
  return { ...value, request: { ...value.request, signature: value.request.signature.slice() }, gap: { ...value.gap } }
}

function copyOffer(value: VaultRestoreOfferOutboxRecord): VaultRestoreOfferOutboxRecord {
  return { ...value, offer: { ...value.offer, signature: value.offer.signature.slice() } }
}
