// How an encrypted mail is kept in the Vault: as the body it arrived with (a notice that it is encrypted) and, after it,
// the armored OpenPGP message. The record is built from the message alone, so every device keeps the same bytes;
// reading it is where the message is opened (decrypt-on-display), with whatever key this device has by then.
import { extractArmor } from './message-crypto.ts'

const MARKER = 'X-Biset-Encrypted: openpgp'

/** The raw body of a stored encrypted mail. Without the armor (a bridge that sent none) it is just the notice. */
export function storedEncryptedBody(notice: string, armor: string | undefined): string {
  return armor ? `Content-Type: text/plain; charset=utf-8\r\n${MARKER}\r\n\r\n${notice}\r\n\r\n${armor.trim()}\r\n` : notice
}

/** The armored message of a stored encrypted mail, or undefined for any other body. */
export function armorOfStoredBody(raw: string): string | undefined {
  if (!raw.startsWith('Content-Type: text/plain; charset=utf-8\r\n' + MARKER + '\r\n\r\n')) return undefined
  const armor = extractArmor(raw)
  return armor.startsWith('-----BEGIN PGP MESSAGE-----') ? armor : undefined
}
