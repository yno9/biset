import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { canonicalBytes } from '../shared/protocol/canonical.ts'

export const VAULT_STORAGE_GROUP_ID = 'urn:biset:vault-storage:v2'
export const VAULT_STORAGE_EPOCH = '0'

/** Stable, endpoint-only KEK. It is independent of DID, domain, server,
 * device, and MLS epoch, and therefore survives every routing transition. */
export function deriveVaultStorageKek(masterSeed: Uint8Array): Uint8Array {
  if (masterSeed.length < 32) throw new TypeError('Vault storage master seed is invalid')
  const salt = sha256(canonicalBytes({ label: 'biset/vault-storage/salt/v2' }))
  return hkdf(sha256, masterSeed, salt, canonicalBytes({ label: 'biset/vault-storage/kek/v2' }), 32)
}
