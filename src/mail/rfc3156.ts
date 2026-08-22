/**
 * Strict, deliberately small RFC 3156 extractor. It only accepts the outer
 * `multipart/encrypted` wrapper and returns the OpenPGP packet; interpreting
 * the decrypted MIME is a separate endpoint concern.
 */
export function extractRfc3156EncryptedPacket(rawRfc5322: Uint8Array): Uint8Array {
  if (!(rawRfc5322 instanceof Uint8Array) || rawRfc5322.length === 0) throw new TypeError('RFC 3156 message is required')
  const outer = splitEntity(new TextDecoder('utf-8').decode(rawRfc5322))
  const contentType = parseContentType(requiredHeader(outer.headers, 'content-type'))
  if (contentType.mediaType !== 'multipart/encrypted' || contentType.params.protocol?.toLowerCase() !== 'application/pgp-encrypted') {
    throw new TypeError('message is not RFC 3156 multipart/encrypted')
  }
  const boundary = contentType.params.boundary
  if (!boundary || boundary.length > 200 || /[\r\n]/.test(boundary)) throw new TypeError('RFC 3156 multipart boundary is invalid')
  const parts = splitMultipart(outer.body, boundary)
  if (parts.length !== 2) throw new TypeError('RFC 3156 multipart/encrypted must contain exactly two parts')
  const versionPart = splitEntity(parts[0]!)
  if (parseContentType(requiredHeader(versionPart.headers, 'content-type')).mediaType !== 'application/pgp-encrypted' || !/^\s*Version:\s*1\s*$/im.test(versionPart.body)) {
    throw new TypeError('RFC 3156 version part is invalid')
  }
  const encryptedPart = splitEntity(parts[1]!)
  if (parseContentType(requiredHeader(encryptedPart.headers, 'content-type')).mediaType !== 'application/octet-stream') throw new TypeError('RFC 3156 encrypted data part is invalid')
  const encoding = (encryptedPart.headers['content-transfer-encoding'] ?? '7bit').toLowerCase()
  if (encoding === 'base64') return decodeMimeBase64(encryptedPart.body)
  if (encoding === '7bit' || encoding === '8bit') {
    const packet = new TextEncoder().encode(encryptedPart.body.trim())
    if (!new TextDecoder().decode(packet).includes('-----BEGIN PGP MESSAGE-----')) throw new TypeError('RFC 3156 non-base64 part must be armored OpenPGP')
    return packet
  }
  throw new TypeError('RFC 3156 encrypted data transfer encoding is unsupported')
}

interface MimeEntity { headers: Record<string, string>; body: string }
interface ContentType { mediaType: string; params: Record<string, string> }

function splitEntity(text: string): MimeEntity {
  const separator = /\r?\n\r?\n/.exec(text)
  if (!separator || separator.index === undefined) throw new TypeError('MIME entity has no header/body separator')
  const headers: Record<string, string> = {}
  for (const line of unfoldHeaders(text.slice(0, separator.index))) {
    const match = /^([!-9;-~]+):\s*(.*)$/.exec(line)
    if (!match) throw new TypeError('MIME header is invalid')
    const name = match[1]!.toLowerCase()
    if (headers[name] !== undefined) throw new TypeError(`duplicate MIME header: ${name}`)
    headers[name] = match[2]!.trim()
  }
  return { headers, body: text.slice(separator.index + separator[0].length) }
}

function unfoldHeaders(block: string): string[] {
  const lines: string[] = []
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line)) {
      if (lines.length === 0) throw new TypeError('MIME header continuation has no header')
      lines[lines.length - 1] += ` ${line.trim()}`
    } else if (line) lines.push(line)
  }
  return lines
}

function requiredHeader(headers: Record<string, string>, name: string): string {
  const value = headers[name]
  if (!value) throw new TypeError(`MIME ${name} header is required`)
  return value
}

function parseContentType(value: string): ContentType {
  const pieces = splitParameters(value)
  const mediaType = pieces.shift()?.trim().toLowerCase()
  if (!mediaType || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType)) throw new TypeError('MIME content type is invalid')
  const params: Record<string, string> = {}
  for (const piece of pieces) {
    const index = piece.indexOf('=')
    if (index < 1) throw new TypeError('MIME content type parameter is invalid')
    const name = piece.slice(0, index).trim().toLowerCase()
    let value = piece.slice(index + 1).trim()
    if (!/^[a-z0-9!#$&^_.+-]+$/i.test(name) || params[name] !== undefined) throw new TypeError('MIME content type parameter is invalid')
    if (value.startsWith('"')) {
      if (value.length < 2 || !value.endsWith('"')) throw new TypeError('MIME quoted parameter is invalid')
      value = value.slice(1, -1).replace(/\\(.)/g, '$1')
    }
    if (!value) throw new TypeError('MIME content type parameter is empty')
    params[name] = value
  }
  return { mediaType, params }
}

function splitParameters(value: string): string[] {
  const pieces: string[] = []
  let quoted = false
  let escaped = false
  let start = 0
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!
    if (escaped) { escaped = false; continue }
    if (quoted && character === '\\') { escaped = true; continue }
    if (character === '"') { quoted = !quoted; continue }
    if (!quoted && character === ';') { pieces.push(value.slice(start, index)); start = index + 1 }
  }
  if (quoted || escaped) throw new TypeError('MIME content type quoting is invalid')
  pieces.push(value.slice(start))
  return pieces
}

function splitMultipart(body: string, boundary: string): string[] {
  const parts: string[] = []
  let active: string[] | undefined
  let closed = false
  for (const originalLine of body.split(/\n/)) {
    const line = originalLine.endsWith('\r') ? originalLine.slice(0, -1) : originalLine
    if (line === `--${boundary}`) {
      if (closed) throw new TypeError('MIME boundary appears after closing delimiter')
      if (active) parts.push(active.join('\n').replace(/\n$/, ''))
      active = []
      continue
    }
    if (line === `--${boundary}--`) {
      if (!active || closed) throw new TypeError('MIME closing boundary is invalid')
      parts.push(active.join('\n').replace(/\n$/, ''))
      active = undefined
      closed = true
      continue
    }
    if (active) active.push(originalLine)
  }
  if (!closed) throw new TypeError('MIME closing boundary is missing')
  return parts
}

function decodeMimeBase64(body: string): Uint8Array {
  const value = body.replace(/[\r\n \t]/g, '')
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new TypeError('MIME base64 body is invalid')
  const output: number[] = []
  for (let index = 0; index < value.length; index += 4) {
    const chunk = value.slice(index, index + 4)
    const padding = chunk.endsWith('==') ? 2 : chunk.endsWith('=') ? 1 : 0
    const word = [...chunk].reduce((accumulator, character) => (accumulator << 6) | (character === '=' ? 0 : base64Index(character)), 0)
    output.push((word >>> 16) & 0xff)
    if (padding < 2) output.push((word >>> 8) & 0xff)
    if (padding === 0) output.push(word & 0xff)
  }
  return new Uint8Array(output)
}

function base64Index(character: string): number {
  const index = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.indexOf(character)
  if (index < 0) throw new TypeError('MIME base64 body is invalid')
  return index
}
