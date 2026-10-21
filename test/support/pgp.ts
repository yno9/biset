// A throwaway OpenPGP key for tests that need "some other person's" key. The app never makes keys at random:
// its own is derived from the generation seed (src/client/pgp/derive.ts).
import { derivePgpKey } from '../../src/client/pgp/derive.ts'
import type { PgpKey } from '../../src/client/pgp/keyring.ts'

export async function generatePgpKey(address: string): Promise<PgpKey> {
  return derivePgpKey(crypto.getRandomValues(new Uint8Array(32)), address)
}
