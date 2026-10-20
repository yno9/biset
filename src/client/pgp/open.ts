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
  /** The signature on it, when it has one. */
  signature?: Decrypted['signature']
}

export interface OpenKeys {
  /** This identity's secret key, binary; undefined when this device has none (yet). */
  privateKey: Uint8Array | undefined
  /** The keys held for the sender (binary public keys), to check the signature with. */
  senderKeys: readonly Uint8Array[]
}

/** The opened mail, or undefined when the body is not an encrypted one or cannot be opened (no key here, not encrypted to it). */
export async function openStoredMail(rawBody: string, keys: OpenKeys): Promise<OpenedMail | undefined> {
  const armored = armorOfStoredBody(rawBody)
  if (!armored || !keys.privateKey) return undefined
  let decrypted: Decrypted
  try { decrypted = await decryptMessage({ armored, privateKey: keys.privateKey, senderKeys: keys.senderKeys }) } catch { return undefined }
  const subject = parseInnerMime(decrypted.plaintext).headers.subject
  return {
    raw: new TextEncoder().encode(decrypted.plaintext),
    ...(subject ? { subject: decodeEncodedWords(subject) } : {}),
    ...(decrypted.signature ? { signature: decrypted.signature } : {}),
  }
}
