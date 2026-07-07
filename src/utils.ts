// ── DOM helpers ───────────────────────────────────────────────────────────────
export function $id(id: string): HTMLElement { return document.getElementById(id) as HTMLElement }
export function $input(id: string): HTMLInputElement { return document.getElementById(id) as HTMLInputElement }
export function $textarea(id: string): HTMLTextAreaElement { return document.getElementById(id) as HTMLTextAreaElement }
export function asInput(el: Element | HTMLElement | null): HTMLInputElement { return el as HTMLInputElement }
export function asHTML(el: Element | EventTarget | null): HTMLElement { return el as HTMLElement }

// ── HTML / text helpers ───────────────────────────────────────────────────────
export function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>')
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
// A conversation is identified by (user, mailbox, contact). Encode it as a URL
// hash, keeping '@' readable (decode passes it through anyway). The mailbox is an
// implementation detail that, for ActivityPub inboxes, equals the account address
// (== user) — so it's dropped as a redundant middle segment, giving the clean
// `#user/contact`. Mail inboxes whose mailbox differs keep all three segments.
function hashSeg(s: string): string { return encodeURIComponent(s).replace(/%40/g, '@') }
function unhashSeg(s: string): string { try { return decodeURIComponent(s) } catch { return s } }

export function inboxToHash(item: { user: string; mailbox: string; contact: string }): string {
  const segs = item.mailbox && item.mailbox === item.user
    ? [item.user, item.contact]
    : [item.user, item.mailbox, item.contact]
  return '#' + segs.map(hashSeg).join('/')
}

export function parseInboxHash(hash: string): { user: string; mailbox: string; contact: string } | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  if (!raw) return null
  const parts = raw.split('/').map(unhashSeg)
  // Short form (`user/contact`): mailbox was dropped because it equalled user.
  if (parts.length === 2 && parts[0] && parts[1]) {
    return { user: parts[0]!, mailbox: parts[0]!, contact: parts[1]! }
  }
  if (parts.length === 3 && parts[0] && parts[1] && parts[2]) {
    return { user: parts[0]!, mailbox: parts[1]!, contact: parts[2]! }
  }
  return null  // 1 part = menu hash (e.g. #account)
}

// ── Avatar helpers ────────────────────────────────────────────────────────────
const palette = ['#e8604a', '#4a90d9', '#5caf6e', '#9b59b6', '#e67e22', '#1abc9c', '#e91e8c', '#607d8b']

export function colorFor(name: string): string {
  let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) & 0xffffff
  return palette[Math.abs(h) % palette.length]!
}

export function avatarStyle(name: string): string { return `background:${colorFor(name)}` }

