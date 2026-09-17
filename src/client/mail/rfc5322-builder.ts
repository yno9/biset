/** Minimal, injection-safe RFC 5322 builder for the Internet-mail relay.
 * MIME attachments and encoded-word display names are intentionally outside
 * this first submission path; raw bytes remain the Vault authority. */
export function buildOutboundRfc5322(input: {
  messageId: string; from: string; to: string[]; subject: string; body: string; inReplyTo?: string; references?: string[]
}): Uint8Array {
  if (!validAddress(input.from) || !input.to.length || input.to.some(address => !validAddress(address))) throw new TypeError('mail submission has an invalid address')
  if (!input.messageId || /[\r\n<>]/.test(input.messageId)) throw new TypeError('mail submission has an invalid message id')
  const lines = [
    `Message-ID: <${input.messageId}@did.md>`,
    `Date: ${new Date().toUTCString()}`,
    `From: ${input.from}`,
    `To: ${input.to.join(', ')}`,
    `Subject: ${header(input.subject)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    ...(input.inReplyTo ? [`In-Reply-To: <${messageRef(input.inReplyTo)}>`] : []),
    ...(input.references?.length ? [`References: ${input.references.slice(-32).map(reference => `<${messageRef(reference)}>`).join(' ')}`] : []),
    '',
    input.body.replace(/\r?\n/g, '\r\n'),
  ]
  return new TextEncoder().encode(lines.join('\r\n'))
}

function validAddress(value: string): boolean { return /^[^<>\s@]+@[^<>\s@]+$/.test(value) }
function header(value: string): string {
  if (/[\r\n]/.test(value)) throw new TypeError('mail header contains a newline')
  return value.slice(0, 998)
}
function messageRef(value: string): string {
  if (!value || /[\r\n<>]/.test(value)) throw new TypeError('mail reply reference is invalid')
  return value
}
