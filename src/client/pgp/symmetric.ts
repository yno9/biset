// Password-encrypted OpenPGP messages, the kind Delta Chat's Secure-Join v3 uses for its first two steps
// (`vc-request-pubkey`, `vc-pubkey`): the password is a shared secret, not a key.
//
// Delta Chat writes a password message as a version 6 session key packet (SKESK: AES-128, OCB, salted S2K with SHA-256) in front of a
// version 2 encrypted data packet (SEIPD: OCB), and opens only a *salted* S2K (anything else is refused, so that a sender cannot make
// it run an expensive one). openpgp.js writes other S2K kinds for a password, so the SKESK is written here (RFC 9580 section 5.3.2)
// and openpgp.js encrypts and signs the data with exactly the session key it holds. An earlier form of this -- a v4 SKESK in front of
// a SEIPD v1 -- was not opened by Delta Chat (its "Modification Detection Code error").
import * as openpgp from 'openpgp'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { ocbEncrypt } from './ocb.ts'
import { ensureArmorChecksum, extractArmor } from './message-crypto.ts'

// 8 KiB chunks, as Delta Chat writes them (chunk size byte 7: 2^(7+6)).
const SEIPD_V2: openpgp.PartialConfig = { aeadProtect: true, aeadChunkSizeByte: 7, preferredAEADAlgorithm: openpgp.enums.aead.ocb, preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes128 }
// What a reader may meet: SEIPD v2 (AEAD OCB with AES-128) from Delta Chat's own symmetric messages.
const READ: openpgp.PartialConfig = { aeadProtect: true, preferredAEADAlgorithm: openpgp.enums.aead.ocb, preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes128 }

export interface SymmetricDecrypted { plaintext: string; signedBy: string[] }

/** The plaintext of `armored`, if one of `passwords` opens it. */
export async function symmetricDecrypt(armored: string, passwords: readonly string[], verificationKeys: readonly Uint8Array[] = []): Promise<SymmetricDecrypted | undefined> {
  const text = extractArmor(armored)
  const keys = await Promise.all(verificationKeys.map(binaryKey => openpgp.readKey({ binaryKey })))
  for (const password of passwords) {
    try {
      const message = await openpgp.readMessage({ armoredMessage: text })
      const result = await openpgp.decrypt({ message, passwords: [password], verificationKeys: keys, config: READ })
      const verified: string[] = []
      for (const signature of result.signatures) if (await signature.verified.then(() => true, () => false)) verified.push(signature.keyID.toHex().toUpperCase())
      return { plaintext: result.data as string, signedBy: verified }
    } catch { /* not this password, or not a password message */ }
  }
  return undefined
}

const utf8 = (text: string) => new TextEncoder().encode(text)

// Salted S2K (RFC 9580 section 3.7.1.2): key = H(salt || password), cut to the cipher's key size. AES-128 needs 16 of SHA-256's 32 bytes.
function saltedS2K(salt: Uint8Array, password: string): Uint8Array {
  const secret = utf8(password)
  const input = new Uint8Array(salt.length + secret.length)
  input.set(salt)
  input.set(secret, salt.length)
  return sha256(input).slice(0, 16)
}

const SKESK_TAG = 0xc3 // new format, packet type 3
const AES128 = 7
const OCB = 2

/** The version 6 session key packet (RFC 9580 section 5.3.2) that seals `sessionKey` under `password`. */
async function sessionKeyPacket(sessionKey: Uint8Array, password: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(8))
  const iv = crypto.getRandomValues(new Uint8Array(15)) // OCB's nonce
  const s2k = new Uint8Array([0x01, 0x08, ...salt]) // salted, SHA-256
  const info = new Uint8Array([SKESK_TAG, 6, AES128, OCB])
  const kek = hkdf(sha256, saltedS2K(salt, password), undefined, info, 16)
  const sealed = await ocbEncrypt(kek, iv, info, sessionKey) // the session key, then the 16-byte tag
  const body = new Uint8Array([6, 1 + 1 + 1 + s2k.length + iv.length, AES128, OCB, s2k.length, ...s2k, ...iv, ...sealed])
  return new Uint8Array([SKESK_TAG, body.length, ...body])
}

// The bytes after the first packet, which is a new-format packet (the session key packet openpgp.js wrote).
function afterFirstPacket(bytes: Uint8Array): Uint8Array {
  const first = bytes[1]!
  let offset = 1, length = 0
  if (first < 192) { length = first; offset += 1 }
  else if (first < 224) { length = ((first - 192) << 8) + bytes[2]! + 192; offset += 2 }
  else if (first === 255) { length = (bytes[2]! << 24) | (bytes[3]! << 16) | (bytes[4]! << 8) | bytes[5]!; offset += 4 }
  else throw new Error('partial-length packet')
  return bytes.slice(offset + length)
}

/** `plaintext` encrypted to `password` and signed by the secret key `signer` (binary), as Delta Chat reads it. */
export async function symmetricEncryptSigned(plaintext: string, password: string, signer: Uint8Array): Promise<string> {
  const signingKey = await openpgp.readPrivateKey({ binaryKey: signer })
  const sessionKey = crypto.getRandomValues(new Uint8Array(16))
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: plaintext }),
    sessionKey: { data: sessionKey, algorithm: 'aes128', aeadAlgorithm: 'ocb' },
    passwords: ['discarded'], // makes openpgp.js write a session key packet, which is dropped below
    signingKeys: signingKey, config: SEIPD_V2, format: 'binary',
  }) as Uint8Array
  const data = afterFirstPacket(new Uint8Array(encrypted))
  const skesk = await sessionKeyPacket(sessionKey, password)
  const armored = openpgp.armor(openpgp.enums.armor.message, new Uint8Array([...skesk, ...data]))
  return ensureArmorChecksum(armored)
}
