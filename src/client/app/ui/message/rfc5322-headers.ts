/**
 * Deliberately small, endpoint-only RFC 5322 header reader.  It is a display
 * metadata helper, not a mail-security parser: raw bytes remain the vault
 * authority and cryptographic MIME handling happens separately.
 */
export interface Rfc5322HeaderSummary {
  subject?: string
  sentAt?: string
  messageId?: string
  inReplyTo?: string
  references: string[]
  /** Parsed from the From: header (RFC 5322 §3.6.2, one mailbox only --
   * group/multi-address From is out of scope for a display helper). Absent
   * when there is no From header, or it doesn't contain a bare
   * `local@domain` address. */
  from?: { email: string; name?: string }
}

export function readRfc5322HeaderSummary(raw: Uint8Array): Rfc5322HeaderSummary {
  const headerBytes = headerSection(raw)
  if (!headerBytes) return { references: [] }
  let text: string
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(headerBytes) } catch { return { references: [] } }
  const fields = unfoldedFields(text)
  const subject = textField(fields.get('subject')?.[0])
  const date = textField(fields.get('date')?.[0])
  const sentAt = date && !Number.isNaN(Date.parse(date)) ? new Date(date).toISOString() : undefined
  const messageId = messageIdentifier(fields.get('message-id')?.[0])
  const inReplyTo = messageIdentifier(fields.get('in-reply-to')?.[0])
  const references = (fields.get('references') ?? []).flatMap(value => identifiers(value)).slice(-32)
  const from = fromMailbox(fields.get('from')?.[0])
  return {
    ...(subject === undefined ? {} : { subject }),
    ...(sentAt === undefined ? {} : { sentAt }),
    ...(messageId === undefined ? {} : { messageId }),
    ...(inReplyTo === undefined ? {} : { inReplyTo }),
    ...(from === undefined ? {} : { from }),
    references,
  }
}

/** "Name <addr@example.com>" or a bare "addr@example.com" -- matches
 * exactly what mail/rfc5322-builder.ts's buildOutboundRfc5322 writes, the
 * one producer this rewrite has for a From header (no encoded-words, no
 * quoted display-name, same "not implemented" scope as the rest of this
 * reader). */
function fromMailbox(value: string | undefined): { email: string; name?: string } | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  const angled = /^(.*)<([^<>\s]+@[^<>\s]+)>$/.exec(trimmed)
  if (angled) {
    const name = angled[1]!.trim()
    return { email: angled[2]!, ...(name ? { name } : {}) }
  }
  if (/^[^<>\s]+@[^<>\s]+$/.test(trimmed)) return { email: trimmed }
  return undefined
}

function headerSection(raw: Uint8Array): Uint8Array | undefined {
  const maximum = Math.min(raw.length, 64 * 1024)
  for (let index = 0; index < maximum; index += 1) {
    if (raw[index] === 10 && raw[index + 1] === 10) return raw.slice(0, index)
    if (raw[index] === 13 && raw[index + 1] === 10 && raw[index + 2] === 13 && raw[index + 3] === 10) return raw.slice(0, index)
  }
  return undefined
}

function unfoldedFields(text: string): Map<string, string[]> {
  const fields = new Map<string, string[]>()
  let currentName: string | undefined
  let currentValue = ''
  const flush = () => {
    if (!currentName) return
    const values = fields.get(currentName) ?? []
    values.push(currentValue)
    fields.set(currentName, values)
  }
  for (const line of text.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && currentName) {
      currentValue += ` ${line.trim()}`
      continue
    }
    flush()
    const colon = line.indexOf(':')
    if (colon <= 0 || !/^[A-Za-z0-9-]+$/.test(line.slice(0, colon))) {
      currentName = undefined
      currentValue = ''
      continue
    }
    currentName = line.slice(0, colon).toLowerCase()
    currentValue = line.slice(colon + 1).trim()
  }
  flush()
  return fields
}

function textField(value: string | undefined): string | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  return trimmed.length === 0 ? undefined : trimmed.slice(0, 8_192)
}

function messageIdentifier(value: string | undefined): string | undefined {
  return identifiers(value ?? '')[0]
}

function identifiers(value: string): string[] {
  const matches = value.match(/<[^<>\r\n]{1,998}>/g) ?? []
  return matches.map(value => value.slice(1, -1))
}
