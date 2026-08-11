// ── Hex ───────────────────────────────────────────────────────────────────────
// Was independently duplicated in 5 files (custom-domain.ts, account-create.ts,
// did/dht/publish.ts, ui/left-pane.ts, did/contacts.ts) — one copy here instead.
export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ── DID service endpoints ────────────────────────────────────────────────────
// did:dht's DidService.serviceEndpoint is always string[] (dht/document.ts);
// did:webvh's WebvhService.serviceEndpoint is string OR string[] (a relay
// service is built as a bare string, a DIDCommMessaging one as a 1-element
// array — webvh/document.ts's buildBisetWebvhState). Method-agnostic callers
// (restore.ts, sync.ts) need the first endpoint either way — this was
// starting to reappear ad hoc (webvh/method-ops.ts, webvh/publish.ts,
// didcomm/resolve.ts) each time new code touched a document from both
// methods; one copy here instead of a fifth.
export function firstServiceEndpoint(se: string | string[]): string {
  return Array.isArray(se) ? (se[0] ?? '') : se
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

// Home-screen icon badge. Single implementation shared with the Service
// Worker (push/shared.ts) — the two used to keep separate copies, which is
// how the background path ended up clearing a badge the foreground had just
// set. Re-exported here so existing `from './utils.ts'` callers don't move.
export { syncAppBadge } from './push/shared.ts'

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
// A conversation permalink is just the *contact* (2026-07-14) — which of the
// user's own logged-in identities/mailboxes it happens to live under is a
// local, self-referential detail with no business being in a URL that's
// fundamentally "who this conversation is with". `main.ts`'s
// matchInboxForHash matches purely on this against whatever's loaded,
// regardless of user/mailbox (an actual multi-identity collision on the same
// contact is a real but rare edge case, and just picks the first match).
//
// DID-preferred (did/contacts.ts's contactIdentityKey): the address is a
// replaceable relay detail, not the identity, so the URL shouldn't be the one
// place that still treats it as the "real" name. Falls back to the literal
// address when no DID is known (most real contacts — Gmail, Mastodon,
// anyone who's never published one).
//
// Single-segment hashes are also how menu pages look (`#account`) —
// main.ts's menuHashFromHash disambiguates via an explicit allowlist of the
// known menu-page names, not by shape, precisely because contact hashes are
// shapeless single segments too now.
import { contactIdentityKey, currentDidForKey } from './did/contacts.ts'
import { isDidIdentityKey } from './did/idkey.ts'

// The segment encoder itself lives in route.ts — the Service Worker builds the
// same permalink for a notification click and must not pull this module's
// contact/DID (and, transitively, openpgp) imports into sw.js.
import { hashSeg, unhashSeg } from './route.ts'

export function inboxToHash(item: { contact: string }): string {
  if (item.contact.startsWith('group:')) return '#' + hashSeg(item.contact)
  // Grouped by identity (so the permalink is the same whichever of a
  // contact's addresses this row happens to be keyed on) but emitted as a
  // REAL identifier — the contact's current DID, or the literal address —
  // never the internal `webvh:{SCID}` key. A URL is copied, pasted and shared:
  // it is squarely on the wire side of PLANWEBVH.md §3.1's boundary, and the
  // internal key means nothing to anything that receives it. Round-tripping
  // still works because the parse side normalizes (main.ts's
  // matchInboxForHash compares contactIdentityKey on both sides), so a
  // pre-move DID in an old link still finds the moved contact.
  const key = contactIdentityKey(item.contact)
  const contactSeg = isDidIdentityKey(key) ? (currentDidForKey(key) ?? item.contact) : key
  return '#' + hashSeg(contactSeg)
}

export function parseInboxHash(hash: string): { contact: string } | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  if (!raw || raw.includes('/')) return null
  return { contact: unhashSeg(raw) }
}

// ── Avatar helpers ────────────────────────────────────────────────────────────
const palette = ['#e8604a', '#4a90d9', '#5caf6e', '#9b59b6', '#e67e22', '#1abc9c', '#e91e8c', '#607d8b']

export function colorFor(name: string): string {
  let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) & 0xffffff
  return palette[Math.abs(h) % palette.length]!
}

export function avatarStyle(name: string): string { return `background:${colorFor(name)}` }

