// Outbound mail submission via a Mail Mediator, wired into buildMailSubmitter
// (identity/bootstrap.ts) as an alternative to CoreMailSubmissionTransport.
// Same `submit(MailSubmissionRequestV1): Promise<MailSubmissionResultV1>`
// interface, so buildMailSubmitter's signer/emailId/mailbox-transition logic
// stays untouched -- only WHERE the bytes go changes. The request's
// deviceId-bound signature is computed by the caller for the core path but
// simply unused here: Mail Mediator's own authorization is the relationship
// kid's authcrypt (server.ts's SUBMIT handler), not this signature.
import { sha256Bytes, bytesToBase64url } from '../protocol/canonical.ts'
import type { MailSubmissionRequestV1, MailSubmissionResultV1 } from '../protocol/mail-submission.ts'
import { ensureMailRelationship } from '../identity/mail-relationship.ts'
import type { MailRelationshipCredentialReader } from './mail-relationship-credential-reader.ts'
import type { MailRelationshipCredentialVaultSink } from './mail-relationship-credential-sink.ts'
import { fetchMediatorInfo, type DidCommSender } from '../didcomm/mediator-transport.ts'
import { submitMail, submitMailStatus } from '../didcomm/mail-mediator-client.ts'
import { decodePeerDid2 } from '../didcomm/peer.ts'
import { defaultFetch } from '../net-fetch.ts'
import type { RecipientSubmitStatus } from '../mail-mediator/protocol.ts'

export interface MailMediatorSubmissionTransportOptions {
  mediatorUrl: string
  /** This identity's shared didCommKid -- the front-door credential
   * ensureMailRelationship authenticates route-bind with, if a
   * relationship for this mediator does not already exist. */
  frontDoor: DidCommSender
  relationshipReader: MailRelationshipCredentialReader
  relationshipSink: MailRelationshipCredentialVaultSink
  fetch?: typeof fetch
  pollIntervalMs?: number
  pollTimeoutMs?: number
}

const DEFAULT_POLL_INTERVAL_MS = 1000
const DEFAULT_POLL_TIMEOUT_MS = 30_000

export class MailMediatorSubmissionTransport {
  private readonly fetchImpl: typeof fetch

  constructor(private readonly options: MailMediatorSubmissionTransportOptions) {
    this.fetchImpl = options.fetch ?? defaultFetch()
  }

  async submit(request: MailSubmissionRequestV1): Promise<MailSubmissionResultV1> {
    const credential = await ensureMailRelationship(
      this.options.relationshipReader, this.options.relationshipSink,
      this.options.frontDoor, request.mailFrom, this.options.mediatorUrl, this.fetchImpl,
    )
    const relationshipXKid = decodePeerDid2(credential.relationshipDid).keyAgreement[0]!
    const relationship: DidCommSender = { did: credential.relationshipDid, xKid: relationshipXKid, xPriv: credential.privateKey }
    const mediator = await fetchMediatorInfo(this.options.mediatorUrl, this.fetchImpl)

    // Content-derived, not random: an identical resubmission (crash before
    // the caller saw a result, e.g.) lands on the SAME idempotency key and
    // is answered from submission-store's cache rather than re-dispatched
    // (PLAN section 9's duplicate-submission scenario).
    const idempotencyKey = bytesToBase64url(sha256Bytes(new TextEncoder().encode(
      `${request.mailFrom}\0${request.rcptTo.join(',')}\0${bytesToBase64url(sha256Bytes(request.rawRfc5322))}`,
    )))
    await submitMail(mediator, relationship, {
      idempotencyKey, mailFrom: request.mailFrom, rcptTo: request.rcptTo, rawRfc5322: request.rawRfc5322,
    }, this.fetchImpl)

    const pollIntervalMs = this.options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS
    const deadline = Date.now() + (this.options.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS)
    while (Date.now() < deadline) {
      const status = await submitMailStatus(mediator, relationship, idempotencyKey, this.fetchImpl)
      if (status.state === 'completed') return aggregate(status.results ?? [])
      await sleep(pollIntervalMs)
    }
    // Still in flight past our own wait budget -- not a failure, just
    // unresolved. `temporary-failure` is the closest existing status this
    // narrow result type has (protocol/mail-submission.ts has no
    // "pending" state); the outbox retry path (buildMailSubmitter's own
    // caller) will re-poll on the identical idempotency key next attempt.
    return { status: 'temporary-failure', occurredAt: new Date().toISOString(), detail: 'submission still in flight' }
  }
}

function aggregate(results: Array<{ recipient: string; status: RecipientSubmitStatus; detail?: string }>): MailSubmissionResultV1 {
  const occurredAt = new Date().toISOString()
  if (results.length > 0 && results.every(r => r.status === 'accepted')) return { status: 'accepted', occurredAt }
  const detail = results
    .filter(r => r.status !== 'accepted')
    .map(r => `${r.recipient}: ${r.status}${r.detail ? ` (${r.detail})` : ''}`)
    .join('; ')
  return { status: 'temporary-failure', occurredAt, ...(detail ? { detail } : {}) }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
