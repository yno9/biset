import { describe, expect, test } from 'bun:test'
import { createBisetCoreFetchHandler } from '../../src/core/app.ts'
import type { VaultDeliveryStore } from '../../src/core/mediation/vault-delivery-store.ts'

const identityId = 'did:web:alice.example'

describe('biset core composition', () => {
  test('does not expose an unauthorised delivery relay when no identity/MLS store is injected', async () => {
    const handler = createBisetCoreFetchHandler({})
    expect((await handler(new Request('https://core.example/healthz'))).status).toBe(200)
    expect((await handler(new Request('https://core.example/v1/vault-delivery/pull', { method: 'POST', body: '{}' }))).status).toBe(404)
  })

  test('routes only delivery operations once an authorised store is injected', async () => {
    const store: VaultDeliveryStore = {
      async append(input) { return { version: 1, identityId, seq: '1', payload: input.payload, payloadHash: input.payloadHash, createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z' } },
      async pull(input) { return { kind: 'items' as const, items: [], nextCursor: input.after, retainedFrom: '1', latestSeq: '0' } },
      async acknowledge() {}, async expire() {},
      async status() { return { identityId, latestSeq: '0', retainedFrom: '1', payloadBytes: 0, pendingItems: 0 } },
    }
    const handler = createBisetCoreFetchHandler({ vaultDeliveryStore: store })
    expect((await handler(new Request('https://core.example/Email/query', { method: 'POST', body: '{}' }))).status).toBe(404)
    expect((await handler(new Request('https://core.example/v1/vault-delivery/pull', { method: 'POST', body: '{}' }))).status).toBe(400)
  })
})
