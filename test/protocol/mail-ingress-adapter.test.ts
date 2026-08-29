import { describe, expect, test } from 'bun:test'
import { MailIngressAdapter } from '../../src/core/adapters/mail.ts'
import { CoreIngressAdapter } from '../../src/core/adapters/ingress.ts'
import { MemoryTrustedDeviceRoster } from '../../src/core/identity/device-roster.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import type { IngressStore } from '../../src/core/mediation/ingress-store.ts'

describe('mail ingress adapter', () => {
  test('keeps RFC 5322 opaque and delegates the recipient snapshot to core', async () => {
    const identityId = 'did:web:alice.example'
    const roster = new MemoryTrustedDeviceRoster()
    await roster.installAcceptedProjection({ version: 1, identityId, selfGroupId: 'self', epoch: '1', acceptedAt: '2026-08-21T00:00:00.000Z', devices: [{ deviceId: 'device-a', deliveryFloor: '1', signingPublicKey: new Uint8Array(32), deviceCredential: new Uint8Array([1]) }] })
    const seen: IngressEnvelopeV1[] = []
    const store: IngressStore = { async offer(value) { seen.push(value) }, async pull() { return [] }, async acknowledge() { throw new Error('unused') }, async expire() { return [] }, async status() { return undefined } }
    const adapter = new MailIngressAdapter(new CoreIngressAdapter(roster, store))
    const raw = new TextEncoder().encode('From: sender@example.test\r\nAutocrypt: opaque\r\n\r\n-----BEGIN PGP MESSAGE-----')

    await adapter.accept({ ingressId: 'mail-1', recipientIdentityId: identityId, createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z', rawRfc5322: raw, smtpEnvelope: 'rcpt=alice@example.test', sourceEvidence: new Uint8Array([1]), metadata: { arc: 'pass' } })

    expect(seen).toHaveLength(1)
    expect(seen[0]?.protectedPayload).toEqual(raw)
    expect(seen[0]?.recipientDeviceSnapshot).toEqual(['device-a'])
    expect(seen[0]?.transportMetadata).toEqual({ smtpEnvelope: 'rcpt=alice@example.test', arc: 'pass' })
  })
})
