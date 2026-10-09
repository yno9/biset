// The innermost layer of a received DIDComm message, once its encryption (if
// any) is undone: a plaintext message, or a signed one (DIDComm v2.1:
// recipients MUST be able to process signed messages, General and Flattened
// JWS alike). One function, so every place a message is opened -- the
// mediator, the device's Pickup, the Vault ingress -- applies the same rules:
//
// - a signature verifies against a key the signer DID's `authentication`
//   references (jws.ts);
// - a message both authcrypted and signed has one sender: the signer's DID
//   MUST be the authcrypt sender's (an error otherwise);
// - Message Layer Addressing Consistency: `from` MUST be the DID of whoever
//   the outer layers authenticated -- the authcrypt sender, else the signer.
import { didOfKid } from '../ids.ts'
import { assertFromMatchesSender, type DidCommPlaintext } from './message.ts'
import { parseDidCommJws, SignatureError, verifyDidCommJws, type SigningKeyResolver } from './jws.ts'

export interface OpenedMessage {
  message: DidCommPlaintext
  /** Who the message is authenticated as: the authcrypt sender's kid, else
   * the signer's. Absent for an anoncrypt (or bare) message nobody signed. */
  senderKid?: string
  /** Set when the message was signed. */
  signerKid?: string
}

/** Opens `bytes` (a decrypted payload, or a message that was never
 * encrypted) as a plaintext or signed DIDComm message. */
export async function openDidCommPayload(bytes: Uint8Array, authcryptSenderKid: string | undefined, resolveSigningKey: SigningKeyResolver): Promise<OpenedMessage> {
  let value: unknown
  try { value = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('DIDComm message is not valid JSON') }
  let signerKid: string | undefined
  const jws = parseDidCommJws(value)
  if (jws) {
    const verified = await verifyDidCommJws(jws, resolveSigningKey)
    signerKid = verified.signerKid
    if (authcryptSenderKid && didOfKid(signerKid) !== didOfKid(authcryptSenderKid)) {
      throw new SignatureError(`the signer (${signerKid}) is not the authcrypt sender (${authcryptSenderKid})`)
    }
    try { value = JSON.parse(new TextDecoder().decode(verified.payload)) } catch { throw new TypeError('signed DIDComm payload is not valid JSON') }
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('DIDComm message must be a JSON object')
  const message = value as DidCommPlaintext
  const senderKid = authcryptSenderKid ?? signerKid
  if (senderKid) assertFromMatchesSender(message, senderKid)
  return { message, ...(senderKid ? { senderKid } : {}), ...(signerKid ? { signerKid } : {}) }
}
