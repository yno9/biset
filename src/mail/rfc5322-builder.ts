/**
 * Deliberately small, plain-text-only outbound RFC 5322 writer -- the
 * counterpart to rfc5322-headers.ts's reader. No RFC 2047 encoded-words
 * (matches the reader's own "not implemented" scope), no MIME multipart, no
 * attachments: this rewrite's core treats rawRfc5322 as fully opaque bytes
 * all the way through (a hard requirement for the eventual PGP path core
 * must never be able to read), so the browser is what has to assemble these
 * bytes -- there is no remote JMAP/SMTP server doing it for the client the
 * way the pre-rewrite version had.
 */
export interface OutboundMessageInput {
  from: string
  fromName?: string
  to: string[]
  subject: string
  body: string
  inReplyTo?: string
  references?: string[]
}

export interface BuiltOutboundMessage {
  rawRfc5322: Uint8Array
  messageId: string
}

export function buildOutboundRfc5322(input: OutboundMessageInput, now: Date = new Date()): BuiltOutboundMessage {
  if (!input.from) throw new TypeError('outbound message requires a from address')
  if (input.to.length === 0) throw new TypeError('outbound message requires at least one recipient')
  const domain = input.from.split('@')[1]
  if (!domain) throw new TypeError('outbound message from address must contain a domain')
  const messageId = `${crypto.randomUUID()}@${domain}`

  const lines: string[] = [
    `From: ${input.fromName ? `${input.fromName} <${input.from}>` : input.from}`,
    `To: ${input.to.join(', ')}`,
    `Subject: ${input.subject}`,
    `Date: ${formatRfc2822Date(now)}`,
    `Message-Id: <${messageId}>`,
  ]
  if (input.inReplyTo) lines.push(`In-Reply-To: <${input.inReplyTo}>`)
  if (input.references?.length) lines.push(`References: ${input.references.map(id => `<${id}>`).join(' ')}`)
  lines.push('Content-Type: text/plain; charset=utf-8')

  const header = lines.join('\r\n') + '\r\n\r\n'
  const rawRfc5322 = new TextEncoder().encode(header + input.body.replace(/\r\n|\r|\n/g, '\r\n'))
  return { rawRfc5322, messageId }
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function formatRfc2822Date(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${WEEKDAYS[date.getUTCDay()]}, ${pad(date.getUTCDate())} ${MONTHS[date.getUTCMonth()]} ${date.getUTCFullYear()} `
    + `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} +0000`
}
