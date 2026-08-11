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

/** Cloudflare returns TXT `content` in DNS *presentation* format, so a record
 * may come back wrapped in quotes (`"did=…"`) or bare (`did=…`) depending on
 * how it was created — both denote the same RDATA. Compare unwrapped, or the
 * "already correct" check never fires and every claim rewrites the record.
 * Production had one of each (`_did.y.biset.md` quoted, the rest bare). */
function unquote(content: string): string {
  const s = content.trim()
  return s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s
}

export class CloudflareAnchor {
  private zoneNameCache?: string

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

  /** The zone this anchor may write to, by name. Config carries only the zone
   * *id*, but deciding whether a record belongs here needs the name — so ask
   * Cloudflare once and remember. Failures aren't cached: a lookup that failed
   * on a network blip should be retried, not turned into a permanent outage. */
  async zoneName(): Promise<string> {
    if (this.zoneNameCache) return this.zoneNameCache
    const resp = await this.request('GET', `/zones/${this.cfg.zoneId}`)
    const body = await resp.json().catch(() => null) as { success?: boolean; result?: { name?: string } } | null
    const name = body?.result?.name
    if (!body?.success || !name) throw new Error(`cloudflare zone lookup failed (status ${resp.status})`)
    this.zoneNameCache = name
    return name
  }

  /** Upserts the `_did.<localpart>.<domain>` TXT record. Rotation-less DIDs mean
   * this is write-once in the common case; the update path only fires if the
   * record already exists with different content (unexpected, but handled
   * rather than left to silently diverge). No-ops when Cloudflare isn't
   * configured, so it's safe to call unconditionally.
   *
   * Throws for an address outside the configured zone — see the guard below.
   * Callers treat DNS as best-effort (the claim is the authority), so this
   * surfaces as a log line, not a failed claim. */
  async writeAnchorTXT(localpart: string, domain: string, did: string): Promise<void> {
    if (!this.enabled()) return
    const name = `_did.${localpart}.${domain}`
    const content = `did=${did}`

    // The anchor holds one zone's credential by design (ANCHOR.md decision 3:
    // scoping the token to a single zone is the only thing confining the blast
    // radius). Posting a name from *another* zone is therefore never going to
    // work — but Cloudflare does not reject it either: **it silently appends
    // the zone name**, so `_did.y.orillo.org` became a live, meaningless
    // `_did.y.orillo.org.biset.md`. Worse, that junk then collides with the
    // next attempt ("An identical record already exists", 400), so the error
    // never points at the real cause and the state can't self-heal. Production
    // accumulated three such records before this guard existed.
    //
    // An address on a domain the operator doesn't run DNS for gets no anchor
    // record from us: its owner publishes `_did.<localpart>.<domain>` in their
    // own zone. That is the same DNS control they already prove during
    // bring-your-own-domain setup, and it keeps the token narrow.
    const zone = await this.zoneName()
    if (name !== zone && !name.endsWith('.' + zone)) {
      throw new Error(`${name} is outside zone ${zone} — not writing. ` +
        `The owner of ${domain} must publish this TXT record themselves.`)
    }

    const listResp = await this.request('GET', `/zones/${this.cfg.zoneId}/dns_records?type=TXT&name=${encodeURIComponent(name)}`)
    const list = await listResp.json().catch(() => null) as { success?: boolean; result?: CfDNSRecord[] } | null
    if (!list?.success) throw new Error(`cloudflare list: bad response (status ${listResp.status})`)

    const rec: CfDNSRecord = { type: 'TXT', name, content, ttl: 300 }
    const existing = list.result?.[0]
    if (existing && unquote(existing.content) === content) return // already correct, nothing to do

    const writeResp = existing
      ? await this.request('PATCH', `/zones/${this.cfg.zoneId}/dns_records/${existing.id}`, rec)
      : await this.request('POST', `/zones/${this.cfg.zoneId}/dns_records`, rec)

    const wr = await writeResp.json().catch(() => null) as { success?: boolean; errors?: { message: string }[] } | null
    if (!wr?.success) {
      throw new Error(`cloudflare write failed (status ${writeResp.status}): ${wr?.errors?.[0]?.message ?? ''}`)
    }
  }

  /** Removes the `_did.<localpart>.<domain>` TXT record — release's half of the
   * pair, so a freed address stops advertising the DID of whoever held it
   * before. Without this the records only ever accumulate: production had 15
   * orphans pointing at DIDs of accounts that no longer existed, plus two live
   * addresses (`5f76`, `6143`) still publishing DIDs their own claims had
   * dropped — i.e. DNS asserting an identity the anchor no longer backed.
   *
   * Deleting nothing is success: release is idempotent (store.ts), and so is
   * this. Same zone rule as writing — an address outside our zone was never
   * ours to publish, so there is nothing of ours to withdraw. */
  async deleteAnchorTXT(localpart: string, domain: string): Promise<void> {
    if (!this.enabled()) return
    const name = `_did.${localpart}.${domain}`
    const zone = await this.zoneName()
    if (name !== zone && !name.endsWith('.' + zone)) return

    const listResp = await this.request('GET', `/zones/${this.cfg.zoneId}/dns_records?type=TXT&name=${encodeURIComponent(name)}`)
    const list = await listResp.json().catch(() => null) as { success?: boolean; result?: CfDNSRecord[] } | null
    if (!list?.success) throw new Error(`cloudflare list: bad response (status ${listResp.status})`)

    // Delete every match, not just the first: Cloudflare allows several TXT
    // records under one name, and a stuck upsert can leave duplicates behind
    // (production held two `_did.test.orillo.org.biset.md` with different DIDs).
    for (const rec of list.result ?? []) {
      const resp = await this.request('DELETE', `/zones/${this.cfg.zoneId}/dns_records/${rec.id}`)
      const body = await resp.json().catch(() => null) as { success?: boolean; errors?: { message: string }[] } | null
      if (!body?.success) {
        throw new Error(`cloudflare delete failed (status ${resp.status}): ${body?.errors?.[0]?.message ?? ''}`)
      }
    }
  }
}
