import type { AdapterIngressOfferV1 } from '../../protocol/ingress.ts'
import type { IdentityId, IngressId } from '../../protocol/ids.ts'
import { sha256Bytes } from '../../protocol/canonical.ts'
import { CoreIngressAdapter } from './ingress.ts'

/**
 * Normalised input from the SMTP listener or upstream JMAP mail source. The
 * adapter deliberately treats RFC 5322/MIME as opaque bytes: OpenPGP,
 * Autocrypt, DeltaChat headers, and MIME interpretation happen only on an
 * endpoint after a signed ingress pull.
 */
export interface MailIngressInput {
  ingressId: IngressId
  recipientIdentityId: IdentityId
  createdAt: string
  expiresAt: string
  rawRfc5322: Uint8Array
  smtpEnvelope: string
  sourceEvidence: Uint8Array
  metadata?: Record<string, string>
}

export class MailIngressAdapter {
  constructor(private readonly ingress: CoreIngressAdapter) {}

  async accept(input: MailIngressInput): Promise<void> {
    if (input.rawRfc5322.length === 0) throw new TypeError('mail ingress raw RFC 5322 payload is required')
    if (!input.smtpEnvelope) throw new TypeError('mail ingress SMTP envelope is required')
    const offer: AdapterIngressOfferV1 = {
      version: 1,
      ingressId: input.ingressId,
      protocol: 'mail',
      recipientIdentityId: input.recipientIdentityId,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      transportMetadata: { smtpEnvelope: input.smtpEnvelope, ...(input.metadata ?? {}) },
      sourceEvidence: input.sourceEvidence.slice(),
      protectedPayload: input.rawRfc5322.slice(),
      protectedPayloadHash: sha256Bytes(input.rawRfc5322),
    }
    await this.ingress.offer(offer)
  }
}
