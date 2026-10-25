// Display helpers ported unchanged from src.bak/utils.ts -- only the pure,
// dependency-free subset the mail UI needs (esc/linkify/formatTime/stripQuoted/
// avatarColor). Left out: everything DID/route/contact-addressed (inboxToHash,
// firstServiceEndpoint, expandDualRelay, etc.) -- none of that exists in this
// rewrite yet, and none of it is a display concern.

export function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/\n/g, '<br>')
}

export function linkify(html: string): string {
  return html.replace(/(https?:\/\/[^\s<"]+|\/[a-zA-Z0-9][^\s<"]*)/g, url =>
    `<a href="${url}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;">${url}</a>`
  )
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })
}

/** The time of a message, with its date when it was not sent today. */
export function formatFullTime(ts: number): string {
  const date = new Date(ts)
  const time = formatTime(ts)
  return date.toDateString() === new Date().toDateString() ? time : `${date.toLocaleDateString('ja-JP', { year: 'numeric', month: 'numeric', day: 'numeric' })} ${time}`
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

export function previewText(body: string, max = 60): string {
  const stripped = stripQuoted(body)
  return (stripped || body).replace(/[\r\n\t]+/g, ' ').trim().slice(0, max)
}

const palette = ['#e8604a', '#4a90d9', '#5caf6e', '#9b59b6', '#e67e22', '#1abc9c', '#e91e8c', '#607d8b']

/** The colours a generated avatar (generated-avatar.tsx) is drawn in: five of the palette. */
export const AVATAR_COLORS = ['#e8604a', '#4a90d9', '#5caf6e', '#9b59b6', '#e67e22'] as const

export function avatarColor(name: string): string {
  let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) & 0xffffff
  return palette[Math.abs(h) % palette.length]!
}

