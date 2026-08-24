/**
 * Deliberately small, display-only plain-text body extractor. Handles the
 * common cases (bare text/plain, or multipart/alternative|mixed with a
 * text/plain leaf); anything else falls back to the raw decoded text. Never
 * throws -- this is a rendering helper over untrusted raw mail, not the
 * RFC 3156 security boundary (`rfc3156.ts`).
 */
export function extractPlainTextBody(raw: Uint8Array): string {
  const text = decodeUtf8(raw)
  const entity = splitEntity(text)
  return bodyOfEntity(entity, 0)
}

interface MimeEntity { headers: Record<string, string>; body: string }

function decodeUtf8(raw: Uint8Array): string {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(raw) } catch { return new TextDecoder('utf-8').decode(raw) }
}

function splitEntity(text: string): MimeEntity {
  const separator = /\r?\n\r?\n/.exec(text)
  if (!separator || separator.index === undefined) return { headers: {}, body: text }
  const headers: Record<string, string> = {}
  for (const line of unfoldHeaders(text.slice(0, separator.index))) {
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim()
  }
  return { headers, body: text.slice(separator.index + separator[0].length) }
}

function unfoldHeaders(block: string): string[] {
  const lines: string[] = []
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && lines.length > 0) lines[lines.length - 1] += ` ${line.trim()}`
    else if (line) lines.push(line)
  }
  return lines
}

function bodyOfEntity(entity: MimeEntity, depth: number): string {
  if (depth > 8) return ''
  const contentTypeRaw = entity.headers['content-type'] ?? 'text/plain'
  const mediaType = contentTypeRaw.split(';')[0]!.trim().toLowerCase()
  if (mediaType.startsWith('multipart/')) {
    // Boundary values are case-sensitive delimiters (RFC 2046 §5.1.1) --
    // must come from the original-case header, not a lowercased copy.
    const boundary = /boundary="?([^";]+)"?/i.exec(contentTypeRaw)?.[1]
    if (!boundary) return ''
    const entities = splitMultipart(entity.body, boundary).map(part => splitEntity(part))
    const plain = entities.find(e => (e.headers['content-type'] ?? 'text/plain').toLowerCase().startsWith('text/plain'))
    const nested = entities.find(e => (e.headers['content-type'] ?? '').toLowerCase().startsWith('multipart/'))
    const chosen = plain ?? nested ?? entities[0]
    return chosen ? bodyOfEntity(chosen, depth + 1) : ''
  }
  if (!mediaType.startsWith('text/')) return ''
  return decodeBody(entity.body, (entity.headers['content-transfer-encoding'] ?? '7bit').toLowerCase())
}

function splitMultipart(body: string, boundary: string): string[] {
  const parts: string[] = []
  let active: string[] | undefined
  for (const originalLine of body.split(/\n/)) {
    const line = originalLine.endsWith('\r') ? originalLine.slice(0, -1) : originalLine
    // The CRLF immediately preceding a boundary delimiter belongs to the
    // delimiter, not the part content (RFC 2046 §5.1.1) -- split() on '\n'
    // already dropped the trailing '\n', so only a stray '\r' is left.
    if (line === `--${boundary}`) { if (active) parts.push(active.join('\n').replace(/\r$/, '')); active = []; continue }
    if (line === `--${boundary}--`) { if (active) parts.push(active.join('\n').replace(/\r$/, '')); active = undefined; continue }
    if (active) active.push(originalLine)
  }
  return parts
}

function decodeBody(body: string, encoding: string): string {
  if (encoding === 'base64') {
    try {
      const binary = atob(body.replace(/[\r\n \t]/g, ''))
      const bytes = Uint8Array.from(binary, character => character.charCodeAt(0))
      return new TextDecoder('utf-8').decode(bytes)
    } catch { return '' }
  }
  if (encoding === 'quoted-printable') return decodeQuotedPrintable(body)
  return body
}

function decodeQuotedPrintable(body: string): string {
  const stripped = body.replace(/=\r?\n/g, '')
  const bytes: number[] = []
  for (let index = 0; index < stripped.length; index += 1) {
    if (stripped[index] === '=' && /^[0-9A-Fa-f]{2}$/.test(stripped.slice(index + 1, index + 3))) {
      bytes.push(Number.parseInt(stripped.slice(index + 1, index + 3), 16))
      index += 2
    } else {
      bytes.push(stripped.charCodeAt(index))
    }
  }
  try { return new TextDecoder('utf-8').decode(new Uint8Array(bytes)) } catch { return stripped }
}
