// A OpenPGP secret key as the app keeps and shows it, and the cut-down public key an Autocrypt header carries. The key itself
// is derived from the generation seed (derive.ts); this is the only other module that reads keys with openpgp.js.
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

/** A secret key as the app keeps and shows it. */
export function describeKey(privateKey: openpgp.PrivateKey): PgpKey {
  return {
    fingerprint: privateKey.getFingerprint().toUpperCase(),
    privateKey: privateKey.write(),
    publicArmor: privateKey.toPublic().armor(),
    userIds: privateKey.getUserIDs(),
  }
}

/** The `keydata` of an Autocrypt header (Autocrypt Level 1, 2.1): the public key as standard base64, cut down to
 * what a peer needs -- the primary key, the user ID for `address` (any one, when none names it), and the newest
 * encryption subkey, without third-party certifications. */
export async function autocryptKeydata(privateKey: Uint8Array, address: string): Promise<string> {
  const key = (await openpgp.readPrivateKey({ binaryKey: privateKey })).toPublic()
  const wanted = address.toLowerCase()
  const named = key.users.filter(user => (user.userID?.email ?? '').toLowerCase() === wanted)
  key.users = (named.length ? named : key.users).slice(0, 1)
  for (const user of key.users) user.otherCertifications = []
  const encryption = await key.getEncryptionKey().catch(() => undefined)
  key.subkeys = encryption && encryption.getKeyID().toHex() !== key.getKeyID().toHex()
    ? key.subkeys.filter(subkey => subkey.getKeyID().toHex() === encryption.getKeyID().toHex())
    : []
  let binary = ''
  for (const byte of key.write()) binary += String.fromCharCode(byte)
  return btoa(binary)
}
