// Password-encrypted OpenPGP messages, the kind Delta Chat's Secure-Join v3 uses for its first two steps
// (`vc-request-pubkey`, `vc-pubkey`): the password is a shared secret, not a key.
//
// Delta Chat opens a symmetric message only when its session key packet (SKESK) has a *Salted* S2K, but openpgp.js writes only
// *Iterated* S2K for a password and refuses the salted kind. So a message is made by hand: the session key is derived from the
// password with the salted S2K, openpgp.js encrypts and signs the data with exactly that session key, its own SKESK is dropped,
// and a v4 SKESK with the salted S2K (and no encrypted session key, so the reader derives the same key) goes in front.
import * as openpgp from 'openpgp'
import { sha256 } from '@noble/hashes/sha2.js'
import { ensureArmorChecksum, extractArmor } from './message-crypto.ts'

const SEIPD_V1: openpgp.PartialConfig = { aeadProtect: false }
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

// Salted S2K (RFC 9580 section 3.7.1.2): key = H(salt || password), cut to the cipher's key size. AES-128 needs 16 of SHA-256's 32 bytes.
function saltedS2K(salt: Uint8Array, password: string): Uint8Array {
  const secret = new TextEncoder().encode(password)
  const input = new Uint8Array(salt.length + secret.length)
  input.set(salt)
  input.set(secret, salt.length)
  return sha256(input).slice(0, 16)
}

// The bytes after the first packet, which is a new-format packet (the SKESK openpgp.js wrote).
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
  const salt = crypto.getRandomValues(new Uint8Array(8))
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: plaintext }),
    sessionKey: { data: saltedS2K(salt, password), algorithm: 'aes128' },
    passwords: ['discarded'], // makes openpgp.js write a session key packet, which is dropped below
    signingKeys: signingKey, config: SEIPD_V1, format: 'binary',
  }) as Uint8Array
  const body = afterFirstPacket(new Uint8Array(encrypted))
  // v4 SKESK: AES-128 (7), salted S2K (type 1) with SHA-256 (8) and the salt.
  const skeskBody = new Uint8Array([0x04, 0x07, 0x01, 0x08, ...salt])
  const skesk = new Uint8Array([0xc3, skeskBody.length, ...skeskBody])
  const armored = openpgp.armor(openpgp.enums.armor.message, new Uint8Array([...skesk, ...body]))
  return ensureArmorChecksum(armored)
}
