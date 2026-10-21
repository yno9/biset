// Opening a stored encrypted mail (stored.ts) for display: decrypt it with this identity's key, check the signature
// against the key we hold for the sender, and hand back the inner MIME as the message to show.
import { armorOfStoredBody } from './stored.ts'
import { decryptMessage, type Decrypted } from './message-crypto.ts'
import { decodeEncodedWords, parseInnerMime } from './mime.ts'

export interface OpenedMail {
  /** The inner MIME (headers and body), to read like any other mail. */
  raw: Uint8Array
  /** The real subject, which the outer mail hides. */
  subject?: string
  /** When it was really written (epoch ms): the outer `Date:` of an encrypted mail is made up (Delta Chat picks a day within the last week). */
  sentAt?: number
  /** A protocol message, not mail to read: a receipt, or the key update Delta Chat sends after a relay change (a `multipart/report` that is a disposition notification). */
  hidden?: boolean
  /** The signature on it, when it has one. */
  signature?: Decrypted['signature']
}

export interface OpenKeys {
  /** This identity's secret keys, binary, the current generation's first: a message may be for an earlier generation. */
  privateKeys: readonly Uint8Array[]
  /** The keys held for the sender (binary public keys), to check the signature with. */
  senderKeys: readonly Uint8Array[]
}

/** The opened mail, or undefined when the body is not an encrypted one or cannot be opened (no key here, not encrypted to it). */
export async function openStoredMail(rawBody: string, keys: OpenKeys): Promise<OpenedMail | undefined> {
  const armored = armorOfStoredBody(rawBody)
  if (!armored) return undefined
  let decrypted: Decrypted | undefined
  for (const privateKey of keys.privateKeys) {
    try { decrypted = await decryptMessage({ armored, privateKey, senderKeys: keys.senderKeys }); break } catch { /* not for this generation's key */ }
  }
  if (!decrypted) return undefined
  const headers = parseInnerMime(decrypted.plaintext).headers
  const sentAt = headers.date ? Date.parse(headers.date) : NaN
  const type = headers['content-type']?.toLowerCase() ?? ''
  return {
    raw: new TextEncoder().encode(decrypted.plaintext),
    ...(type.startsWith('multipart/report') && type.includes('disposition-notification') ? { hidden: true } : {}),
    ...(headers.subject ? { subject: decodeEncodedWords(headers.subject) } : {}),
    ...(Number.isNaN(sentAt) ? {} : { sentAt }),
    ...(decrypted.signature ? { signature: decrypted.signature } : {}),
  }
}
