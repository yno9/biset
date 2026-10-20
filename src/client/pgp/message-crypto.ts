// Encrypting to and decrypting from OpenPGP keys, the way Delta Chat does it: every message is signed and also
// encrypted to ourselves (our other devices read what we sent), with SEIPD v1 (Delta Chat uses v2 only when every
// recipient supports it). Keys are binary OpenPGP packets: a transferable secret key for ours, public keys for the peers'.
import * as openpgp from 'openpgp'

const ENCRYPT_CONFIG: openpgp.PartialConfig = { aeadProtect: false }

export class NotEncryptedToUsError extends Error {}

/** The armored message to `recipients` (binary public keys) and to the signer itself, signed by `signer` (a binary secret key). */
export async function encryptMessage(input: { plaintext: string; recipients: readonly Uint8Array[]; signer: Uint8Array }): Promise<string> {
  const signingKey = await openpgp.readPrivateKey({ binaryKey: input.signer })
  const encryptionKeys = [...(await Promise.all(input.recipients.map(binaryKey => openpgp.readKey({ binaryKey })))), signingKey.toPublic()]
  const armored = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: input.plaintext }),
    encryptionKeys, signingKeys: signingKey, config: ENCRYPT_CONFIG,
  })
  return ensureArmorChecksum(armored as string)
}

export interface Decrypted {
  plaintext: string
  /** The signature on the message, if any: the signing key's id, and whether it verified against a key we hold for the sender. */
  signature?: { keyId: string; verified: boolean }
}

/** Decrypts with `privateKey`; checks the signature against `senderKeys` (binary public keys). */
export async function decryptMessage(input: { armored: string; privateKey: Uint8Array; senderKeys?: readonly Uint8Array[] }): Promise<Decrypted> {
  const message = await openpgp.readMessage({ armoredMessage: extractArmor(input.armored) })
  const decryptionKeys = await openpgp.readPrivateKey({ binaryKey: input.privateKey })
  const verificationKeys = await Promise.all((input.senderKeys ?? []).map(binaryKey => openpgp.readKey({ binaryKey })))
  let result: Awaited<ReturnType<typeof openpgp.decrypt>>
  try { result = await openpgp.decrypt({ message, decryptionKeys, verificationKeys, config: ENCRYPT_CONFIG }) } catch (error) {
    if (/session key|decrypt/i.test(error instanceof Error ? error.message : '')) throw new NotEncryptedToUsError('the message is not encrypted to this key')
    throw error
  }
  const [first] = result.signatures
  let signature: Decrypted['signature']
  if (first) signature = { keyId: first.keyID.toHex().toUpperCase(), verified: await first.verified.then(() => true, () => false) }
  return { plaintext: result.data as string, ...(signature ? { signature } : {}) }
}

/** The armored block inside surrounding text (a bridge may add a notice around it). */
export function extractArmor(text: string): string {
  const start = text.indexOf('-----BEGIN PGP MESSAGE-----')
  const endMarker = '-----END PGP MESSAGE-----'
  const end = text.indexOf(endMarker)
  return start >= 0 && end >= 0 ? text.slice(start, end + endMarker.length) : text
}

// OpenPGP CRC-24 (RFC 9580 section 6.1) over the packet bytes.
function crc24(bytes: Uint8Array): number {
  let crc = 0xb704ce
  for (const byte of bytes) {
    crc ^= byte << 16
    for (let bit = 0; bit < 8; bit++) {
      crc <<= 1
      if (crc & 0x1000000) crc ^= 0x1864cfb
    }
  }
  return crc & 0xffffff
}

/** Adds the armor's CRC-24 line when it is missing. openpgp.js leaves it out of AEAD (SEIPD v2) messages, and chatmail's
 * filtermail then takes the message for an unencrypted one and refuses it. */
export function ensureArmorChecksum(armored: string): string {
  const lines = armored.replace(/\r\n/g, '\n').split('\n')
  const begin = lines.findIndex(line => line.startsWith('-----BEGIN PGP MESSAGE-----'))
  const end = lines.findIndex(line => line.startsWith('-----END PGP MESSAGE-----'))
  if (begin < 0 || end < 0) return armored
  if (/^=[A-Za-z0-9+/]{4}$/.test(lines[end - 1] ?? '')) return armored
  let blank = begin + 1
  while (blank < end && lines[blank]!.trim() !== '') blank++
  const base64 = lines.slice(blank + 1, end).join('').replace(/\s/g, '')
  if (!base64) return armored
  let bytes: Uint8Array
  try { bytes = Uint8Array.from(atob(base64), char => char.charCodeAt(0)) } catch { return armored }
  const crc = crc24(bytes)
  const line = '=' + btoa(String.fromCharCode((crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff))
  return [...lines.slice(0, end), line, ...lines.slice(end)].join(armored.includes('\r\n') ? '\r\n' : '\n')
}
