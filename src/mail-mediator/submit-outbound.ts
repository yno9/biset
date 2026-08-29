// Wires smtp-client.ts's deliverMail into the `submitOutbound` shape
// server.ts's SUBMIT handler expects: per-recipient
// accepted/temporary-failure/permanent-failure, not deliverMail's own
// per-domain result shape (PLAN_biset-mail-mediator.md section 12 --
// "複数recipientの部分成功を単一booleanへ潰さない").
import { deliverMail, groupRecipientsByDomain, type DeliverMailOptions } from './smtp-client.ts'
import type { SubmissionRecord } from './submission-store.ts'
import type { SubmitResultBody } from './protocol.ts'

type RecipientResult = NonNullable<SubmitResultBody['results']>[number]

export function buildSmtpSubmitOutbound(
  hostname: string, options: Omit<DeliverMailOptions, 'hostname'> = {},
): (record: SubmissionRecord) => Promise<RecipientResult[]> {
  return async record => {
    const byDomain = groupRecipientsByDomain(record.rcptTo)
    const deliveries = await deliverMail({ hostname, ...options }, {
      mailFrom: record.mailFrom, rcptTo: record.rcptTo, rawRfc5322: record.rawRfc5322,
    })
    const results: RecipientResult[] = []
    for (const delivery of deliveries) {
      if (delivery.outcome === 'error') {
        // No connection was ever made for this domain (no MX, or the
        // handshake/TLS itself failed) -- every recipient grouped under
        // it is temporary-failure, not silently dropped.
        for (const address of byDomain.get(delivery.domain) ?? []) {
          results.push({ recipient: address, status: 'temporary-failure', detail: delivery.error })
        }
        continue
      }
      for (const address of delivery.accepted) results.push({ recipient: address, status: 'accepted' })
      for (const { address, reply } of delivery.rejected) {
        // SMTP reply code convention: 5xx is permanent, 4xx is
        // retry-later. A malformed/missing reply code is treated as
        // temporary -- the safer default when the failure's nature is
        // itself unclear.
        const status = reply.startsWith('5') ? 'permanent-failure' : 'temporary-failure'
        results.push({ recipient: address, status, detail: reply })
      }
    }
    return results
  }
}
