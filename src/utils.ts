// ── Hex ───────────────────────────────────────────────────────────────────────
// Was independently duplicated in 5 files (custom-domain.ts, account-create.ts,
// did/publish.ts, ui/left-pane.ts, did/contacts.ts) — one copy here instead.
export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
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

// Distinguishes our own JS-driven scrolling (scrollToFocused, scroll-to-top/
// bottom buttons, ...) from genuine user scrolling (including mobile momentum,
// which keeps firing 'scroll' events for an unpredictable stretch after the
// finger lifts — there's no fixed "recent touch" window that reliably covers
// it). Call markProgrammaticScroll() right before any outer.scrollTo/scrollTop
// write; a scroll listener elsewhere can then check isProgrammaticScroll() to
// tell whether the current event is one of ours.
let _programmaticScrollUntil = 0
export function markProgrammaticScroll(durationMs = 700): void {
  _programmaticScrollUntil = Date.now() + durationMs
}
export function isProgrammaticScroll(): boolean {
  return Date.now() < _programmaticScrollUntil
}

// Home-screen icon badge (Badging API — installed PWA only, iOS 16.4+/Android
// Chrome). No-op elsewhere; wrapped since older browsers lack the methods.
export function syncAppBadge(count: number): void {
  const nav = navigator as any
  if (count > 0) nav.setAppBadge?.(count).catch(() => {})
  else nav.clearAppBadge?.().catch(() => {})
}

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
import { contactIdentityKey } from './did/contacts.ts'

// ':' is a legal, unreserved-enough character in a URI *fragment* per RFC 3986
// (pchar includes ':' and '@') — encodeURIComponent escapes it anyway since
// it's a generic component encoder, but did:dht:... reads far better
// unescaped, same as '@' already is below.
function hashSeg(s: string): string { return encodeURIComponent(s).replace(/%40/g, '@').replace(/%3A/gi, ':') }
function unhashSeg(s: string): string { try { return decodeURIComponent(s) } catch { return s } }

export function inboxToHash(item: { contact: string }): string {
  const contactSeg = item.contact.startsWith('group:') ? item.contact : contactIdentityKey(item.contact)
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

