// DNS-based identity anchor: the address→DID binding lives in a
// `_did.<localpart>.<domain>` TXT record (`did=<did>`) rather than a bespoke
// relay-hosted endpoint, so discovering an address's DID doesn't depend on that
// address's relay operator staying up or honest — DNS is a commodity,
// swappable, and self-hostable by whoever owns the domain.
//
// Ported from go-jmapserver's cloudflare.go, which lived in the shared relay
// library despite **only go-didanchor ever importing it** (ANCHOR.md: one of
// the concrete examples of "the DID code is scattered" — it was simply in the
// wrong home).
//
// This is the only place a Cloudflare credential is used. ANCHOR.md decision 3
// accepts that it now shares a process with live traffic (the mediator and the
// pkarr gateway), reversing DID.md's "anchor stays small and boring by design,
// indefinitely" — **so scoping the token to a single zone with DNS:Edit only is
// mandatory, not advisory**: it is the only thing left confining the blast
// radius if that process is compromised.
export interface CloudflareConfig {
  apiToken?: string
  zoneId?: string
}

interface CfDNSRecord {
  id?: string
  type: string
  name: string
  content: string
  ttl: number
}

const API = 'https://api.cloudflare.com/client/v4'
const TIMEOUT_MS = 10_000

export class CloudflareAnchor {
  constructor(private cfg: CloudflareConfig) {}

  enabled(): boolean {
    return !!this.cfg.apiToken && !!this.cfg.zoneId
  }

  private request(method: string, path: string, body?: unknown): Promise<Response> {
    return fetch(API + path, {
      method,
      headers: { Authorization: `Bearer ${this.cfg.apiToken}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  }

  /** Upserts the `_did.<localpart>.<domain>` TXT record. Rotation-less DIDs mean
   * this is write-once in the common case; the update path only fires if the
   * record already exists with different content (unexpected, but handled
   * rather than left to silently diverge). No-ops when Cloudflare isn't
   * configured, so it's safe to call unconditionally. */
  async writeAnchorTXT(localpart: string, domain: string, did: string): Promise<void> {
    if (!this.enabled()) return
    const name = `_did.${localpart}.${domain}`
    const content = `did=${did}`

    const listResp = await this.request('GET', `/zones/${this.cfg.zoneId}/dns_records?type=TXT&name=${encodeURIComponent(name)}`)
    const list = await listResp.json().catch(() => null) as { success?: boolean; result?: CfDNSRecord[] } | null
    if (!list?.success) throw new Error(`cloudflare list: bad response (status ${listResp.status})`)

    const rec: CfDNSRecord = { type: 'TXT', name, content, ttl: 300 }
    const existing = list.result?.[0]
    if (existing && existing.content === content) return // already correct, nothing to do

    const writeResp = existing
      ? await this.request('PATCH', `/zones/${this.cfg.zoneId}/dns_records/${existing.id}`, rec)
      : await this.request('POST', `/zones/${this.cfg.zoneId}/dns_records`, rec)

    const wr = await writeResp.json().catch(() => null) as { success?: boolean; errors?: { message: string }[] } | null
    if (!wr?.success) {
      throw new Error(`cloudflare write failed (status ${writeResp.status}): ${wr?.errors?.[0]?.message ?? ''}`)
    }
  }
}
