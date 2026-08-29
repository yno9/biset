// Shared DKIM message-signing helper for tests (dkim.test.ts and
// smtp-listener.test.ts) -- signs a fixture message using the exact same
// canonicalization exports dkim.ts itself verifies against.
import { sha256 } from '@noble/hashes/sha2.js'
import { canonicalizeHeaderRelaxed, canonicalizeBodyRelaxed, type RawHeader } from '../../../src/mail-mediator/dkim.ts'

export function latin1ToBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
  return out
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

export interface SignOptions {
  domain: string
  selector: string
  algorithm: 'rsa-sha256' | 'ed25519-sha256'
  sign(input: Uint8Array): Promise<Uint8Array> | Uint8Array
}

/** Returns the raw signed message (headers + DKIM-Signature + body) as a
 * Latin-1-encoded byte string, exactly what an SMTP DATA payload looks
 * like on the wire. */
export async function buildSignedMessage(headers: RawHeader[], body: string, options: SignOptions): Promise<Uint8Array> {
  const bodyHash = sha256(latin1ToBytes(canonicalizeBodyRelaxed(body)))
  const headerNames = headers.map(h => h.name)
  const withoutB = `v=1; a=${options.algorithm}; c=relaxed/relaxed; d=${options.domain}; s=${options.selector}; h=${headerNames.join(':')}; bh=${bytesToBase64(bodyHash)}; b=`
  const signingLines = headers.map(canonicalizeHeaderRelaxed)
  signingLines.push(canonicalizeHeaderRelaxed({ name: 'DKIM-Signature', value: withoutB }))
  const signingInput = latin1ToBytes(signingLines.join('\r\n'))
  const signature = await options.sign(signingInput)
  const dkimHeaderValue = `${withoutB}${bytesToBase64(signature)}`

  const rawHeaderLines = [`DKIM-Signature:${dkimHeaderValue}`, ...headers.map(h => `${h.name}:${h.value}`)]
  const raw = `${rawHeaderLines.join('\r\n')}\r\n\r\n${body}`
  return latin1ToBytes(raw)
}
