// The MIME entity inside an OpenPGP message (RFC 3156), the way Delta Chat reads and writes it: the real headers
// ("protected headers": Subject, From, To, Date, Message-ID, In-Reply-To, References, Chat-*, Autocrypt,
// Autocrypt-Gossip) followed by the body. Delta Chat trusts only these inner headers of an encrypted mail.

export interface InnerMime {
  /** The headers, names lowercased; when one repeats, the first wins (`autocrypt-gossip` is in `gossip`). */
  headers: Record<string, string>
  /** Every `Autocrypt-Gossip` header value. */
  gossip: string[]
  /** The first text part, decoded. */
  body: string
  /** The other parts of a multipart entity. */
  attachments: Array<{ contentType: string; filename?: string; bytes: Uint8Array }>
}

/** A header value fit for a header line: non-ASCII is RFC 2047 encoded-word (UTF-8, base64); line breaks never survive. */
export function encodeHeaderValue(value: string): string {
  const flat = value.replace(/[\r\n]+/g, ' ').trim()
  if (/^[\x20-\x7e]*$/.test(flat)) return flat
  const bytes = new TextEncoder().encode(flat)
  // Words of at most 45 bytes, cut on character boundaries, so a line stays under the 76 column limit.
  const words: string[] = []
  let start = 0
  while (start < bytes.length) {
    let end = Math.min(start + 45, bytes.length)
    while (end < bytes.length && (bytes[end]! & 0xc0) === 0x80) end--
    let binary = ''
    for (const byte of bytes.slice(start, end)) binary += String.fromCharCode(byte)
    words.push(`=?UTF-8?B?${btoa(binary)}?=`)
    start = end
  }
  return words.join('\r\n ')
}

/** `Autocrypt:` / `Autocrypt-Gossip:` value: `addr=…; keydata=` and the base64 folded on continuation lines. */
export function keydataHeader(name: 'Autocrypt' | 'Autocrypt-Gossip', addr: string, keydata: string, preferEncrypt = false): string {
  const chunks: string[] = []
  for (let index = 0; index < keydata.length; index += 72) chunks.push(keydata.slice(index, index + 72))
  return `${name}: addr=${addr};${preferEncrypt ? ' prefer-encrypt=mutual;' : ''} keydata=${chunks.join('\r\n ')}`
}

/** CRLF text of an entity: `headers` (name and value, written as given after the value is encoded) then a plain text body.
 * `lines` are pre-built header lines (such as `keydataHeader`'s) written as they are. */
export function buildInnerMime(input: { headers?: Array<[name: string, value: string]>; lines?: string[]; text: string }): string {
  const headers = (input.headers ?? []).map(([name, value]) => {
    if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(name)) throw new TypeError(`bad header name ${name}`)
    return `${name}: ${encodeHeaderValue(value)}`
  })
  return [
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    ...headers,
    ...(input.lines ?? []),
  ].join('\r\n') + '\r\n\r\n' + input.text
}

/** Decodes RFC 2047 encoded-words (`=?UTF-8?B?…?=`, `=?…?Q?…?=`); anything it cannot decode is left as it was. */
export function decodeEncodedWords(value: string): string {
  return value.replace(/(=\?[^?]+\?[BbQq]\?[^?]*\?=)\s+(?==\?)/g, '$1').replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (word, charset: string, encoding: string, text: string) => {
    try {
      let bytes: Uint8Array
      if (encoding.toUpperCase() === 'B') bytes = Uint8Array.from(atob(text), char => char.charCodeAt(0))
      else {
        const out: number[] = []
        const source = text.replace(/_/g, ' ')
        for (let index = 0; index < source.length; index++) {
          if (source[index] === '=' && /^[0-9A-Fa-f]{2}$/.test(source.slice(index + 1, index + 3))) { out.push(parseInt(source.slice(index + 1, index + 3), 16)); index += 2 }
          else out.push(source.charCodeAt(index))
        }
        bytes = new Uint8Array(out)
      }
      return new TextDecoder(charset.toLowerCase()).decode(bytes)
    } catch { return word }
  })
}

/** Parses the plaintext of an OpenPGP message. Text without a header block is just a body. */
export function parseInnerMime(text: string): InnerMime {
  const result: InnerMime = { headers: {}, gossip: [], body: '', attachments: [] }
  if (!/^[A-Za-z][\w-]*:[ \t]/.test(text.split(/\r?\n/, 1)[0] ?? '')) { result.body = text; return result }
  parseEntity(result, text, 0)
  return result
}

const MAX_DEPTH = 8

function unfold(block: string): string[] {
  const lines: string[] = []
  for (const line of block.split(/\r?\n/)) {
    if (line && /^[ \t]/.test(line) && lines.length) lines[lines.length - 1] += ' ' + line.trim()
    else lines.push(line)
  }
  return lines
}

function splitMultipart(body: string, boundary: string): string[] {
  const parts: string[] = []
  const chunks = body.split('--' + boundary)
  for (let index = 1; index < chunks.length; index++) {
    const chunk = chunks[index]!
    if (chunk.startsWith('--')) break
    parts.push(chunk.replace(/^\r?\n/, '').replace(/\r?\n$/, ''))
  }
  return parts
}

function parseEntity(out: InnerMime, text: string, depth: number): void {
  if (depth > MAX_DEPTH) return
  const separator = /\r?\n\r?\n/.exec(text)
  const headerBlock = separator ? text.slice(0, separator.index) : text
  const body = separator ? text.slice(separator.index + separator[0].length) : ''
  let encoding = '', charset = 'utf-8', contentType = '', disposition = '', filename = ''
  for (const line of unfold(headerBlock)) {
    const match = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(line)
    if (!match) continue
    const name = match[1]!.toLowerCase(), value = match[2]!.trim()
    if (depth === 0) {
      if (name === 'autocrypt-gossip') out.gossip.push(value)
      else if (!(name in out.headers)) out.headers[name] = value
    }
    if (name === 'content-transfer-encoding') encoding = value.toLowerCase()
    else if (name === 'content-type') {
      contentType = value
      charset = /charset="?([^";\s]+)/i.exec(value)?.[1]?.toLowerCase() ?? charset
      filename = /name="?([^";]+)"?/i.exec(value)?.[1]?.trim() ?? filename
    } else if (name === 'content-disposition') {
      disposition = value.toLowerCase()
      filename = /filename="?([^";]+)"?/i.exec(value)?.[1]?.trim() ?? filename
    }
  }
  const boundary = /boundary="?([^";]+)"?/i.exec(contentType)?.[1]
  if (/^multipart\//i.test(contentType) && boundary) {
    for (const part of splitMultipart(body, boundary)) parseEntity(out, part, depth + 1)
    return
  }
  if ((contentType === '' || /^text\//i.test(contentType)) && !disposition.includes('attachment')) {
    if (!out.body) out.body = decodeBody(body, encoding, charset)
    return
  }
  const bytes = encoding === 'base64' ? base64Bytes(body) : new TextEncoder().encode(body)
  out.attachments.push({ contentType: contentType.split(';')[0]!.trim(), ...(filename ? { filename } : {}), bytes })
}

function base64Bytes(value: string): Uint8Array {
  try { return Uint8Array.from(atob(value.replace(/\s+/g, '')), char => char.charCodeAt(0)) } catch { return new Uint8Array() }
}

function decodeBody(body: string, encoding: string, charset: string): string {
  const decode = (bytes: Uint8Array) => { try { return new TextDecoder(charset).decode(bytes) } catch { return new TextDecoder().decode(bytes) } }
  if (encoding === 'base64') return decode(base64Bytes(body))
  if (encoding === 'quoted-printable') {
    const joined = body.replace(/=\r?\n/g, '')
    const bytes: number[] = []
    for (let index = 0; index < joined.length; index++) {
      if (joined[index] === '=' && /^[0-9A-Fa-f]{2}$/.test(joined.slice(index + 1, index + 3))) { bytes.push(parseInt(joined.slice(index + 1, index + 3), 16)); index += 2 }
      else bytes.push(joined.charCodeAt(index))
    }
    return decode(new Uint8Array(bytes))
  }
  return body
}
