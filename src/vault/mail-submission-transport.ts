import { defaultFetch } from '../net-fetch.ts'
import type { MailSubmissionRequestV1, MailSubmissionResultV1 } from '../protocol/mail-submission.ts'
import { decodeMailSubmissionResultWire, encodeMailSubmissionRequestWire } from '../protocol/mail-submission-wire.ts'

export interface CoreMailSubmissionTransportOptions {
  baseUrl: string
  fetch?: typeof fetch
}

/** Browser transport for signed outbound mail submission only -- signing
 * happens in the caller (identity/bootstrap.ts's buildMailSubmitter), this
 * is a thin POST wrapper, same shape as CoreIngressTransport/
 * CoreVaultDeliveryTransport. */
export class CoreMailSubmissionTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrl: string

  constructor(options: CoreMailSubmissionTransportOptions) {
    if (!options.baseUrl) throw new TypeError('core mail submission base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetchValue = options.fetch ?? defaultFetch()
  }

  async submit(request: MailSubmissionRequestV1): Promise<MailSubmissionResultV1> {
    return decodeMailSubmissionResultWire(await this.post('/v1/mail/submit', encodeMailSubmissionRequestWire(request)))
  }

  private async post(path: string, body: string): Promise<string> {
    const response = await this.fetchValue(`${this.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    const text = await response.text()
    if (!response.ok) throw new Error(`core mail submission request failed (${response.status}): ${text.slice(0, 256)}`)
    return text
  }
}
