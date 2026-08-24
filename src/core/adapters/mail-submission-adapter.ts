import { deliverMail, type MailDeliveryResult } from './mail-smtp-client.ts'
import type { MailSubmissionAuthorizer } from '../identity/authorizers.ts'
import type { MailSubmissionRequestV1, MailSubmissionResultV1 } from '../../protocol/mail-submission.ts'

/**
 * The authenticated narrow-API surface for outbound mail: a device's signed
 * MailSubmissionRequestV1 is verified against the identity's trusted-device
 * roster BEFORE deliverMail() ever touches the network -- an unauthenticated
 * caller cannot make this process dial an arbitrary MX, which is what would
 * turn it into an open relay.
 */
export class CoreMailSubmissionAdapter {
  constructor(
    private readonly authorizer: MailSubmissionAuthorizer,
    private readonly hostname: string,
    private readonly deliverMailFn: typeof deliverMail = deliverMail,
  ) {
    if (!hostname) throw new TypeError('mail submission adapter requires a hostname for outbound EHLO')
  }

  async submit(request: MailSubmissionRequestV1): Promise<MailSubmissionResultV1> {
    if (!(await this.authorizer.verify(request))) throw new Error('mail submission is not authorised')
    const results = await this.deliverMailFn(
      { hostname: this.hostname },
      { mailFrom: request.mailFrom, rcptTo: request.rcptTo, rawRfc5322: request.rawRfc5322 },
    )
    return collapseResults(results)
  }
}

function collapseResults(results: MailDeliveryResult[]): MailSubmissionResultV1 {
  const occurredAt = new Date().toISOString()
  const failures = results.filter(result => result.outcome === 'error' || result.rejected.length > 0)
  if (failures.length === 0) return { status: 'accepted', occurredAt }
  const detail = failures.map(result => result.error ?? `${result.domain}: ${result.rejected.map(r => `${r.address} (${r.reply})`).join(', ')}`).join('; ')
  return { status: 'temporary-failure', occurredAt, detail: detail.slice(0, 2048) }
}
