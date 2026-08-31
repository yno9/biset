// Composes the Conversation Group DS engine (store.ts) with both transports
// this repo has for it: the narrow HTTP handler (http.ts, Phase 2a) and the
// DIDComm plaintext handler (didcomm.ts, Phase 2b) -- same signature
// verifier, same store, same authorizer calls either way
// (PLAN_biset-mls-ds.md's "engine is transport-agnostic" premise).
import type { DidCommPlaintext } from '../didcomm/message.ts'
import type { SendDidCommMessageOptions } from '../didcomm/front-door-send.ts'
import { Ed25519ConversationDsSignatureVerifier, type ConversationDeviceSigningPublicKeyResolver } from './authorizer.ts'
import { handleConversationDsMessage } from './didcomm.ts'
import { createConversationDeliveryHttpHandler } from './http.ts'
import { SqliteConversationDeliveryService } from './store.ts'
import { ConversationWebvhSigningKeyResolver } from './webvh-signing-key-resolver.ts'

export interface ConversationDsDeploymentOptions {
  databasePath: string
  signingKeys?: ConversationDeviceSigningPublicKeyResolver
  /** This DS's own DID -- the `from` on every DIDComm response/problem-report
   * it sends, and the identity a MimiDeliveryService entry (webvh-routing.ts)
   * should point at. */
  self: string
  /** This DS's own DIDComm sending identity, for message-notify fan-out
   * (fanout.ts). Not the same key as `signingKeys` verifies incoming
   * requests against -- that's each MEMBER's device credential; this is the
   * DS's OWN keyAgreement key for outbound delivery. */
  sendOpts: SendDidCommMessageOptions
}

export function createConversationDsDeployment(options: ConversationDsDeploymentOptions) {
  const ds = SqliteConversationDeliveryService.open(options.databasePath)
  const verifier = new Ed25519ConversationDsSignatureVerifier(options.signingKeys ?? new ConversationWebvhSigningKeyResolver())
  return {
    ds,
    fetch: createConversationDeliveryHttpHandler(ds, verifier),
    /** Feeds one already-decrypted DIDComm plaintext through the same
     * engine the HTTP handler uses. The caller owns how a plaintext gets
     * here (mediator pickup loop, direct ingress, etc.) -- not yet wired to
     * any inbound transport (PLAN_biset-mls-ds.md Phase 3). */
    handleDidCommMessage: (msg: DidCommPlaintext): Promise<DidCommPlaintext | null> =>
      handleConversationDsMessage(ds, verifier, msg, options.self, options.sendOpts),
    close(): void { ds.close() },
  }
}
