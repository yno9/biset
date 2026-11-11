// How an encrypted mail is kept in the Vault: as the body it arrived with (a notice that it is encrypted) and, after it,
// the armored OpenPGP message. The record is built from the message alone, so every device keeps the same bytes;
// reading it is where the message is opened (decrypt-on-display), with whatever key this device has by then.
import { extractArmor } from './message-crypto.ts'

const MARKER = 'X-Biset-Encrypted: openpgp'
const DMARC_MARKER = 'X-Biset-Dmarc: pass'
const HEAD = 'Content-Type: text/plain; charset=utf-8\r\n' + MARKER + '\r\n'

/** The raw body of a stored encrypted mail. Without the armor (a bridge that sent none) it is just the notice. */
export function storedEncryptedBody(notice: string, armor: string | undefined, dmarcPass = false): string {
  return armor ? `Content-Type: text/plain; charset=utf-8\r\n${MARKER}\r\n${dmarcPass ? DMARC_MARKER + '\r\n' : ''}\r\n${notice}\r\n\r\n${armor.trim()}\r\n` : notice
}

/** Whether the bridge saw the mail pass DMARC: only then is a key it carries the sender's (PROTOCOL.md §5.5, the same rule as Autocrypt). */
export function dmarcPassOfStoredBody(raw: string): boolean { return raw.startsWith(HEAD) && raw.slice(HEAD.length).startsWith(DMARC_MARKER + '\r\n') }

/** The armored message of a stored encrypted mail, or undefined for any other body. */
export function armorOfStoredBody(raw: string): string | undefined {
  if (!raw.startsWith(HEAD) || !/^(?:X-Biset-Dmarc: pass\r\n)?\r\n/.test(raw.slice(HEAD.length))) return undefined
  const armor = extractArmor(raw)
  return armor.startsWith('-----BEGIN PGP MESSAGE-----') ? armor : undefined
}
