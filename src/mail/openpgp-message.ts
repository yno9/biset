import * as openpgp from 'openpgp'
import { readOpenPgpPrivateCredential } from './openpgp-credential.ts'
import type { OpenPgpPrivateCredentialV1 } from '../vault/openpgp-credential.ts'

export interface OpenPgpEncryptedMessageInput {
  credential: OpenPgpPrivateCredentialV1
  /** RFC 3156/MIME parsing supplies the extracted OpenPGP packet bytes here. */
  encryptedMessage: Uint8Array
  verificationArmoredKeys?: string[]
  /** Use only when the surrounding protocol requires an authenticated sender. */
  requireValidSignature?: boolean
}

interface OpenPgpMessageSignature {
  keyId: string
  valid: boolean
}

export interface OpenPgpDecryptedMessage {
  plaintext: Uint8Array
  signatures: OpenPgpMessageSignature[]
}

/**
 * Endpoint-only OpenPGP packet decrypt/verify primitive. It intentionally
 * accepts an already extracted packet rather than RFC 5322: MIME and
 * DeltaChat/Autocrypt interpretation remain a separate mail projector.
 */
export async function decryptOpenPgpMessage(input: OpenPgpEncryptedMessageInput): Promise<OpenPgpDecryptedMessage> {
  if (!(input.encryptedMessage instanceof Uint8Array) || input.encryptedMessage.length === 0) throw new TypeError('OpenPGP encrypted message is required')
  const privateKey = await readOpenPgpPrivateCredential(input.credential)
  const verificationKeys = input.verificationArmoredKeys === undefined
    ? undefined
    : await Promise.all(input.verificationArmoredKeys.map(async armoredKey => {
      if (!armoredKey) throw new TypeError('OpenPGP verification key is empty')
      return openpgp.readKey({ armoredKey })
    }))
  let message: openpgp.Message<Uint8Array>
  try { message = await openpgp.readMessage({ binaryMessage: input.encryptedMessage }) } catch { throw new TypeError('OpenPGP encrypted message packet is invalid') }
  let decrypted: Awaited<ReturnType<typeof openpgp.decrypt>>
  try {
    decrypted = await openpgp.decrypt({
      message,
      decryptionKeys: privateKey,
      ...(verificationKeys === undefined ? {} : { verificationKeys }),
      format: 'binary',
    })
  } catch {
    throw new TypeError('OpenPGP message cannot be decrypted')
  }
  if (!(decrypted.data instanceof Uint8Array)) throw new TypeError('OpenPGP message plaintext is not binary data')
  const signatures = await Promise.all(decrypted.signatures.map(async signature => {
    try {
      await signature.verified
      return { keyId: signature.keyID.toHex().toUpperCase(), valid: true }
    } catch {
      return { keyId: signature.keyID.toHex().toUpperCase(), valid: false }
    }
  }))
  if (input.requireValidSignature && (signatures.length === 0 || signatures.some(signature => !signature.valid))) {
    throw new TypeError('OpenPGP message lacks a valid required signature')
  }
  return { plaintext: decrypted.data.slice(), signatures }
}
