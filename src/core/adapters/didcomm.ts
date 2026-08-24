import type { AdapterIngressOfferV1 } from '../../protocol/ingress.ts'
import type { IdentityId, IngressId } from '../../protocol/ids.ts'
import { sha256Bytes } from '../../protocol/canonical.ts'
import { CoreIngressAdapter } from './ingress.ts'

/**
 * Normalised input from the DIDComm HTTP endpoint. The adapter treats the
 * packed JWE as opaque bytes, same as mail.ts treats raw RFC 5322: unpacking
 * (authcrypt decrypt, sender verification, message-type dispatch) happens
 * only on an endpoint after a signed ingress pull (PLAN.md §6.1's scope --
 * external ingress, OOB, bootstrap, short control -- is entirely a property
 * of what a device does with the plaintext, nothing this untrusted adapter
 * needs to know).
 */
export interface DidCommIngressInput {
  ingressId: IngressId
  recipientIdentityId: IdentityId
  createdAt: string
  expiresAt: string
  /** The packed JWE (didcomm/crypto.ts's DidCommJWE), as the exact bytes it
   * arrived in -- never re-serialized, so protectedPayloadHash matches what
   * a device that later fetches the raw bytes back can independently verify. */
  packedJwe: Uint8Array
  sourceEvidence: Uint8Array
  metadata?: Record<string, string>
}

export class DidCommIngressAdapter {
  constructor(private readonly ingress: CoreIngressAdapter) {}

  async accept(input: DidCommIngressInput): Promise<void> {
    if (input.packedJwe.length === 0) throw new TypeError('DIDComm ingress packed JWE payload is required')
    const offer: AdapterIngressOfferV1 = {
      version: 1,
      ingressId: input.ingressId,
      protocol: 'didcomm',
      recipientIdentityId: input.recipientIdentityId,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      transportMetadata: { ...(input.metadata ?? {}) },
      sourceEvidence: input.sourceEvidence.slice(),
      protectedPayload: input.packedJwe.slice(),
      protectedPayloadHash: sha256Bytes(input.packedJwe),
    }
    await this.ingress.offer(offer)
  }
}
