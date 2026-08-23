// Client side of the roster-install narrow HTTP API
// (core/identity/roster-http.ts), mirroring core-mls-delivery-transport.ts's
// shape.
import { encodeRosterInstallWire, type RosterInstallV1 } from '../core/identity/roster-install.ts'

export type RosterInstallHttpOutcome = 'installed' | 'already-current' | 'rejected'

export interface CoreRosterInstallTransportOptions {
  baseUrl: string
  fetch?: typeof fetch
}

export class CoreRosterInstallTransport {
  private readonly fetchValue: typeof fetch
  private readonly baseUrl: string

  constructor(options: CoreRosterInstallTransportOptions) {
    if (!options.baseUrl) throw new TypeError('core roster install base URL is required')
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetchValue = options.fetch ?? fetch
  }

  async install(input: RosterInstallV1): Promise<RosterInstallHttpOutcome> {
    const response = await this.fetchValue(`${this.baseUrl}/v1/roster/install`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: encodeRosterInstallWire(input),
    })
    const text = await response.text()
    if (response.status === 403) return 'rejected'
    if (!response.ok) throw new Error(`core roster install request failed (${response.status}): ${text.slice(0, 256)}`)
    const parsed = JSON.parse(text) as { outcome?: unknown }
    if (parsed.outcome !== 'installed' && parsed.outcome !== 'already-current') throw new Error('core roster install returned an unrecognized outcome')
    return parsed.outcome
  }
}
