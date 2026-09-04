import type { DeviceId, IdentityId } from './ids.ts'

/**
 * A device's signed request to submit an already-composed, already-locally-
 * committed outbound message for delivery. `rawRfc5322` is opaque bytes to
 * core, same as inbound mail -- PGP/MIME encryption (deferred, separate
 * peer-key-discovery design gap) would happen before this request is built,
 * not here.
 */
export interface MailSubmissionRequestV1 {
  version: 1
  identityId: IdentityId
  deviceId: DeviceId
  mailFrom: string
  rcptTo: string[]
  rawRfc5322: Uint8Array
  submittedAt: string
  signature: Uint8Array
}

/**
 * Collapsed from the outbound SMTP client's per-domain-group results.
 * `accepted` only when every domain group fully succeeded; anything else is
 * `temporary-failure` with `detail` summarizing what happened -- there is no
 * `permanent-failure` here yet, the same "don't invent a permanence signal
 * this layer can't actually distinguish" reasoning already used for the
 * inbound listener's 452-vs-451 split (mail-smtp-protocol.ts).
 */
export interface MailSubmissionResultV1 {
  status: 'accepted' | 'temporary-failure'
  occurredAt: string
  detail?: string
}
