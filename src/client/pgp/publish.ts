// Publishing the user's OpenPGP public key at the mail bridge (didmail
// PROTOCOL.md §11), which serves it over WKD so that anyone can find
// `user@{apex}`'s key. It is a DIDComm message to the address's bridge DID,
// authcrypt'd by this device like any other.
import { sendFrontDoorMessage } from '../didcomm/front-door-send.ts'
import { resolveMailBridgeDid } from '../didcomm/address-resolver.ts'

const OPENPGP_KEY_PUBLISH = 'https://did.md/openpgp-key/1.0/publish'

export interface PublishPgpKeyInput {
  /** The user's own mail address (`label@apex`). */
  address: string
  gateways: readonly string[]
  /** The armored public key, or null to withdraw it. */
  publicArmor: string | null
  fromKid: string
  x25519PrivateKey: Uint8Array
  fetch?: typeof fetch
}

export async function publishPgpKey(input: PublishPgpKeyInput): Promise<void> {
  const bridgeDid = await resolveMailBridgeDid(input.address, input.gateways, input.fetch)
  const sent = await sendFrontDoorMessage(bridgeDid, OPENPGP_KEY_PUBLISH, { key: input.publicArmor }, {
    fromKid: input.fromKid, x25519PrivateKey: input.x25519PrivateKey, ...(input.fetch ? { fetch: input.fetch } : {}),
  })
  if (!sent.ok) throw new Error(`The mail bridge did not take the key: ${sent.error}`)
}
