// ── Hex ───────────────────────────────────────────────────────────────────────
// Was independently duplicated in 5 files (custom-domain.ts, account-create.ts,
// did/dht/publish.ts, ui/left-pane.ts, did/contacts.ts) — one copy here instead.
// Moved to protocol/canonical.ts (2026-08-31) so DOM-less deploy units can
// use it without this file's DOM-dependent half; re-exported here unchanged
// for every existing caller of utils.ts.
export { hexToBytes, bytesToHex } from './protocol/canonical.ts'

// ── DID service endpoints ────────────────────────────────────────────────────
// did:dht's DidService.serviceEndpoint is always string[] (dht/document.ts);
// did:webvh's WebvhService.serviceEndpoint is string OR string[] (a relay
// service is built as a bare string, a DIDCommMessaging one as a 1-element
// array — webvh/document.ts's buildBisetWebvhState). Method-agnostic callers
// (restore.ts, sync.ts) need the first endpoint either way — this was
// starting to reappear ad hoc (webvh/method-ops.ts, webvh/publish.ts,
// didcomm/resolve.ts) each time new code touched a document from both
// methods; one copy here instead of a fifth.
export function firstServiceEndpoint(se: string | string[] | { uri?: string }): string {
  // Three shapes, all valid DID Core: a bare string (biset's own JMAPRelay
  // entries), an array (what a DIDCommMessaging service used to be published
  // as), and the object DIDComm v2 defines — `{uri, accept, routingKeys}` —
  // which is what one is published as now (webvh/document.ts).
  if (Array.isArray(se)) return se[0] ?? ''
  if (typeof se === 'object' && se !== null) return se.uri ?? ''
  return se
}

// ── Relay pairs ───────────────────────────────────────────────────────────────
// A bare apex like "biset.md" (no scheme, no mail./ap. prefix already) names a
// HOME domain, not one relay — mail and ActivityPub are separate services
// there (mail.<apex> / ap.<apex>), the same pairing #new's onboarding
// (account-create.ts) already provisions together. Returns both candidate
// relay URLs, or null if `raw` already names one specific relay (has a
// scheme, or already starts with mail./ap.) — used by both the "+ New JMAP
// account" Sign up and Log in paths (left-pane.ts, ui/custom-domain.ts) to
// offer the same "one home identity, two relays" shortcut #new has always had.
export function expandDualRelay(raw: string): [string, string] | null {
  const trimmed = raw.trim().replace(/\/$/, '')
  if (!trimmed || /^https?:\/\//i.test(trimmed)) return null
  if (/^(mail|ap)\./i.test(trimmed)) return null
  if (!trimmed.includes('.')) return null
  return [`https://mail.${trimmed}`, `https://ap.${trimmed}`]
}

// ── DOM helpers ───────────────────────────────────────────────────────────────
// Home-screen icon badge (push/shared.ts's syncAppBadge) dropped: no push
// implementation exists in this rewrite yet (PLAN.md scope), and nothing
// calls it.

export function $id(id: string): HTMLElement { return document.getElementById(id) as HTMLElement }
export function $input(id: string): HTMLInputElement { return document.getElementById(id) as HTMLInputElement }
export function $textarea(id: string): HTMLTextAreaElement { return document.getElementById(id) as HTMLTextAreaElement }
export function asInput(el: Element | HTMLElement | null): HTMLInputElement { return el as HTMLInputElement }
export function asHTML(el: Element | EventTarget | null): HTMLElement { return el as HTMLElement }

// ── HTML / text helpers ───────────────────────────────────────────────────────
// Used both for HTML text content and inside quoted attribute values
// (e.g. title="${esc(x)}") throughout the UI layer — escape quotes too, or
// attacker-controlled data (a remote sender's From address, etc.) placed in
// an attribute can break out of it and inject arbitrary attributes/script.
export function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/\n/g, '<br>')
}

// Shared by deltachat/avatar.ts and processing.ts (message attachments) — one
// bytes→data-URL encoder so both stay in sync. Doubles as an attachment's
// download href (data: URLs work fine with <a download>).
export function bytesToDataUrl(bytes: Uint8Array, contentType: string): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return `data:${contentType || 'application/octet-stream'};base64,${btoa(bin)}`
}

export function linkify(html: string): string {
  return html.replace(/(https?:\/\/[^\s<"]+|\/[a-zA-Z0-9][^\s<"]*)/g, url =>
    `<a href="${url}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;">${url}</a>`
  )
}

export function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })
}

export function stripQuoted(text: string): string {
  const lines = text.split('\n')
  const out: string[] = []
  for (const line of lines) {
    const trimmed = line.trimStart()
    if (trimmed.startsWith('>')) continue
    if (/^On .+wrote:$/.test(trimmed)) continue
    out.push(line)
  }
  return out.join('\n').trim()
}

// The one-line form of a body: what the conversation list shows for a message
// the thread view renders in full.
//
// It lives beside stripQuoted, and goes through it, because the two renderers
// drifting apart is exactly the bug this replaced — the list showed
// "test > On Aug 11, 2026, at 7:52, y <y@..." for a message the thread showed
// as "test". A preview is a shorter view of the same message, not a different
// reading of it.
//
// stripQuoted runs BEFORE newlines are collapsed: it works line by line, and
// there are no lines left once \n has become a space.
//
// A reply whose whole body is a quote strips to nothing, and the original is
// used then rather than leaving the row blank — an empty preview says less
// than a quote does, and that is the degenerate case, not the one this fixes.
export function previewText(body: string, max = 60): string {
  const stripped = stripQuoted(body)
  return (stripped || body).replace(/[\r\n\t]+/g, ' ').trim().slice(0, max)
}

// ── JMAP ID helpers ───────────────────────────────────────────────────────────
export function mailboxNameFromId(id: string): string {
  return id.startsWith('mbx-') ? id.slice(4).replace(/~/g, '/') : ''
}

// ── Inbox permalink (hash) ──────────────────────────────────────────────────────
// Dropped: inboxToHash/parseInboxHash depended on did/contacts.ts's own
// contact→DID address book, which doesn't exist in this rewrite yet (no
// contacts feature ported — PLAN.md scope). Nothing calls either function
// right now; route.ts's hashSeg/unhashSeg are still there for whatever
// eventually needs this.

// ── Avatar helpers ────────────────────────────────────────────────────────────
const palette = ['#e8604a', '#4a90d9', '#5caf6e', '#9b59b6', '#e67e22', '#1abc9c', '#e91e8c', '#607d8b']

export function colorFor(name: string): string {
  let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) & 0xffffff
  return palette[Math.abs(h) % palette.length]!
}

export function avatarStyle(name: string): string { return `background:${colorFor(name)}` }
