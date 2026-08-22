import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { SqliteIngressStore } from '../../src/core/mediation/sqlite-ingress-store.ts'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressAuthorizer } from '../../src/core/mediation/ingress-store.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../../src/protocol/ingress.ts'

const path = `/tmp/biset-ingress-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const authorizer: IngressAuthorizer = { async verifyPull(pull) { return ['device-a', 'device-b'].includes(pull.recipientDeviceId) }, async verify() { return true } }
const envelope: IngressEnvelopeV1 = { version: 1, ingressId: 'ingress-1', protocol: 'mail', recipientIdentityId: identityId, recipientDeviceSnapshot: ['device-a', 'device-b'], createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z', transportMetadata: { envelope: 'opaque' }, sourceEvidence: new Uint8Array([1]), protectedPayload: new Uint8Array([2, 3]), protectedPayloadHash: sha256Bytes(new Uint8Array([2, 3])) }
const ack: IngressAckV1 = { version: 1, ingressId: 'ingress-1', protectedPayloadHash: sha256Bytes(new Uint8Array([2, 3])), recipientDeviceId: 'device-a', vaultEventId: 'event-1', checkpointId: 'checkpoint-1', ackedAt: '2026-08-21T01:00:00.000Z', signature: new Uint8Array([9]) }
function pull(recipientDeviceId: string): IngressPullV1 { return { version: 1, identityId, recipientDeviceId, requestedAt: '2026-08-21T01:00:00.000Z', signature: new Uint8Array([8]) } }

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

describe('SQLite ingress store', () => {
  test('survives restart only while the external body remains pending', async () => {
    const first = SqliteIngressStore.open(path, authorizer)
    await first.offer(envelope)
    first.close()
    const restarted = SqliteIngressStore.open(path, authorizer)
    expect(await restarted.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))).toEqual([envelope])
    await restarted.acknowledge(ack, new Date('2026-08-21T01:00:00.000Z'))
    expect(await restarted.status('ingress-1')).toMatchObject({ status: 'vault-ingested', payloadRetained: false })
    restarted.close()
  })

  test('does not resurrect envelope metadata or body after ACK across a restart', async () => {
    const first = SqliteIngressStore.open(path, authorizer)
    await first.offer(envelope)
    await first.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))
    await first.acknowledge(ack, new Date('2026-08-21T01:00:00.000Z'))
    first.close()
    const restarted = SqliteIngressStore.open(path, authorizer)
    expect(await restarted.pull(pull('device-b'), new Date('2026-08-21T02:00:00.000Z'))).toEqual([])
    expect(await restarted.status('ingress-1')).toEqual({ ingressId: 'ingress-1', identityId, status: 'vault-ingested', expiresAt: '2026-08-22T00:00:00.000Z', payloadRetained: false })
    restarted.close()
  })

  test('expires a body into a tombstone under the same bounded policy', async () => {
    const store = SqliteIngressStore.open(path, authorizer)
    await store.offer({ ...envelope, expiresAt: '2026-08-21T00:01:00.000Z' })
    expect(await store.expire(new Date('2026-08-21T00:01:00.000Z'))).toMatchObject([{ status: 'expired', payloadRetained: false }])
    expect(await store.pull(pull('device-a'), new Date('2026-08-21T00:02:00.000Z'))).toEqual([])
    store.close()
  })

  test('persists a short exclusive ingress claim without retaining a second copy of the body', async () => {
    const store = SqliteIngressStore.open(path, authorizer, { maxPayloadBytes: 100, maxIdentityPayloadBytes: 100, maxIdentityPendingItems: 10, claimLeaseMs: 1_000 })
    await store.offer(envelope)
    expect(await store.pull(pull('device-a'), new Date('2026-08-21T01:00:00.000Z'))).toHaveLength(1)
    store.close()
    const restarted = SqliteIngressStore.open(path, authorizer, { maxPayloadBytes: 100, maxIdentityPayloadBytes: 100, maxIdentityPendingItems: 10, claimLeaseMs: 1_000 })
    expect(await restarted.pull(pull('device-b'), new Date('2026-08-21T01:00:00.500Z'))).toEqual([])
    expect(await restarted.pull(pull('device-b'), new Date('2026-08-21T01:00:01.000Z'))).toHaveLength(1)
    restarted.close()
  })
})
