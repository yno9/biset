// The user's OpenPGP key (decryption and signing happen on the device, never
// at the mail bridge -- didmail PROTOCOL.md §5.3, §5.4, §11). This is the
// only module that touches openpgp.js for keys: it makes a key, takes in an
// existing one, and reads the public half out of a stored secret key.
//
// A secret key is kept as the binary OpenPGP packets, unprotected: the Vault
// object it lives in is already encrypted to the identity's devices, so a
// passphrase on top would only be one more thing to lose.
import * as openpgp from 'openpgp'

export interface PgpKey {
  /** v4: 40 hex characters, upper case. */
  fingerprint: string
  /** The secret key, binary, with no passphrase. */
  privateKey: Uint8Array
  /** The public half, ASCII-armored (what is published and shared). */
  publicArmor: string
  /** The `Name <email>` user IDs the key carries. */
  userIds: string[]
}

/** A new key for `address`: Curve25519 (EdDSA signing, ECDH encryption), no expiry. */
export async function generatePgpKey(address: string, name?: string): Promise<PgpKey> {
  const { privateKey } = await openpgp.generateKey({
    type: 'curve25519', userIDs: [{ ...(name ? { name } : {}), email: address }], format: 'object',
  })
  return describe(privateKey)
}

/** A key the user already has: armored or binary, with the passphrase it is protected by (if any). */
export async function importPgpKey(key: string | Uint8Array, passphrase?: string): Promise<PgpKey> {
  let privateKey: openpgp.PrivateKey
  try {
    privateKey = typeof key === 'string' ? await openpgp.readPrivateKey({ armoredKey: key }) : await openpgp.readPrivateKey({ binaryKey: key })
  } catch (error) {
    throw new Error(`That is not an OpenPGP secret key (${error instanceof Error ? error.message : String(error)}).`)
  }
  if (!privateKey.isDecrypted()) {
    if (!passphrase) throw new Error('The key is protected by a passphrase.')
    try { privateKey = await openpgp.decryptKey({ privateKey, passphrase }) } catch { throw new Error('The passphrase does not unlock the key.') }
  }
  await privateKey.getEncryptionKey().catch(() => { throw new Error('The key cannot decrypt (no usable encryption subkey).') })
  return describe(privateKey)
}

/** The key behind stored secret-key bytes. */
export async function readPgpKey(privateKey: Uint8Array): Promise<PgpKey> {
  return describe(await openpgp.readPrivateKey({ binaryKey: privateKey }))
}

function describe(privateKey: openpgp.PrivateKey): PgpKey {
  return {
    fingerprint: privateKey.getFingerprint().toUpperCase(),
    privateKey: privateKey.write(),
    publicArmor: privateKey.toPublic().armor(),
    userIds: privateKey.getUserIDs(),
  }
}

/** Whether the key names `address` among its user IDs (what a WKD client checks). */
export function keyNamesAddress(key: Pick<PgpKey, 'userIds'>, address: string): boolean {
  const wanted = address.toLowerCase()
  return key.userIds.some(id => (/<([^>]+)>/.exec(id)?.[1] ?? id).trim().toLowerCase() === wanted)
}
