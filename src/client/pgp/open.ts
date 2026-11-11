// Opening a stored encrypted mail (stored.ts) for display: decrypt it with this identity's key, check the signature
// against the key we hold for the sender, and hand back the inner MIME as the message to show.
import { armorOfStoredBody } from './stored.ts'
import { base64ToBytes } from '../../protocol/base64.ts'
import { decryptMessage, type Decrypted } from './message-crypto.ts'
import { publicKeyOfAttachment } from './keyring.ts'
import { avatarOfHeader, decodeEncodedWords, displayNameOfFrom, isMimeEntity, parseInnerMime } from './mime.ts'

export interface OpenedMail {
  /** The inner MIME (headers and body), to read like any other mail. */
  raw: Uint8Array
  /** The real subject, which the outer mail hides. */
  subject?: string
  /** When it was really written (epoch ms): the outer `Date:` of an encrypted mail is made up (Delta Chat picks a day within the last week). */
  sentAt?: number
  /** A protocol message, not mail to read: a receipt, or the key update Delta Chat sends after a relay change (a `multipart/report` that is a disposition notification). */
  hidden?: boolean
  /** The sender's own name, from the `From:` inside -- only when the signature held against a key we have for the sender, so it is theirs. */
  fromName?: string
  /** The sender's picture from the `Chat-User-Avatar:` inside (a data URL), or `null` when it removed it; absent when the message says nothing, or the signature did not hold. */
  avatar?: string | null
  /** The sender's public key, which the mail carried as an attachment inside the encryption and signed with (so the key and the mail are
   * one person's): offered only when the bridge saw it pass DMARC and no key held for the sender verified it. A key to keep, as Autocrypt's. */
  senderKey?: string
  /** The signature on it, when it has one. */
  signature?: Decrypted['signature']
}

export interface OpenKeys {
  /** This identity's secret keys, binary, the current generation's first: a message may be for an earlier generation. */
  privateKeys: readonly Uint8Array[]
  /** The keys held for the sender (binary public keys), to check the signature with. */
  senderKeys: readonly Uint8Array[]
  /** The mail address the sender stands for, and whether the bridge saw the mail pass DMARC: with both, a key attached inside is looked for. */
  sender?: { address: string; dmarcPass: boolean }
}

/** The opened mail, or undefined when the body is not an encrypted one or cannot be opened (no key here, not encrypted to it). */
export async function openStoredMail(rawBody: string, keys: OpenKeys): Promise<OpenedMail | undefined> {
  const armored = armorOfStoredBody(rawBody)
  if (!armored) return undefined
  let decrypted: Decrypted | undefined, usedKey: Uint8Array | undefined
  for (const privateKey of keys.privateKeys) {
    try { decrypted = await decryptMessage({ armored, privateKey, senderKeys: keys.senderKeys }); usedKey = privateKey; break } catch { /* not for this generation's key */ }
  }
  if (!decrypted || !usedKey) return undefined
  const inner = parseInnerMime(decrypted.plaintext)
  const headers = inner.headers
  // A client with no Autocrypt (Roundcube, Enigmail) attaches its key to the mail. It is the sender's when it is for the sender's address,
  // the mail passed DMARC, and the mail is signed with it.
  let senderKey: string | undefined
  if (keys.sender?.dmarcPass && decrypted.signature?.verified !== true) {
    for (const attachment of inner.attachments) {
      const candidate = await publicKeyOfAttachment(attachment.bytes, keys.sender.address)
      if (!candidate) continue
      const signed = await decryptMessage({ armored, privateKey: usedKey, senderKeys: [base64ToBytes(candidate)] }).catch(() => undefined)
      if (signed?.signature?.verified !== true) continue
      senderKey = candidate; decrypted = signed
      break
    }
  }
  const sentAt = headers.date ? Date.parse(headers.date) : NaN
  const type = headers['content-type']?.toLowerCase() ?? ''
  return {
    // Inline PGP is the text of the mail with no headers of its own: it is given one, or its first lines would be read as headers.
    raw: new TextEncoder().encode(isMimeEntity(decrypted.plaintext) ? decrypted.plaintext : `Content-Type: text/plain; charset=utf-8\r\n\r\n${decrypted.plaintext}`),
    ...(type.startsWith('multipart/report') && type.includes('disposition-notification') ? { hidden: true } : {}),
    ...(headers.subject ? { subject: decodeEncodedWords(headers.subject) } : {}),
    ...(Number.isNaN(sentAt) ? {} : { sentAt }),
    ...(decrypted.signature?.verified === true && displayNameOfFrom(headers.from) ? { fromName: displayNameOfFrom(headers.from)! } : {}),
    ...(decrypted.signature?.verified === true && avatarOfHeader(headers['chat-user-avatar']) !== undefined ? { avatar: avatarOfHeader(headers['chat-user-avatar'])! } : {}),
    ...(senderKey ? { senderKey } : {}),
    ...(decrypted.signature ? { signature: decrypted.signature } : {}),
  }
}
