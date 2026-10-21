// This identity's OpenPGP keys: the key of the current generation seed, and those of the earlier generations (a device was
// removed since), which are still needed to read what was encrypted to them. They are derived (derive.ts), not stored.
import { derivePgpKey } from './derive.ts'
import type { PgpKey } from './keyring.ts'

export interface GenerationSeeds {
  /** The seed the DID document names now; undefined while this device cannot use one (yet). */
  current(): Promise<Uint8Array | undefined>
  /** Every seed the Vault holds, in any order. */
  all(): Promise<readonly Uint8Array[]>
}

export interface OwnPgp {
  /** The key of the current generation, or undefined while there is no usable seed. */
  current(): Promise<PgpKey | undefined>
  /** The keys of every generation this device holds a seed for, the current one first. */
  all(): Promise<PgpKey[]>
}

export function ownPgp(address: string, seeds: GenerationSeeds): OwnPgp {
  // A derivation costs a key generation and signatures: keep the result for as long as the seed is the same.
  const cache = new Map<string, Promise<PgpKey>>()
  const keyOf = (seed: Uint8Array): Promise<PgpKey> => {
    const id = Array.from(seed, byte => byte.toString(16).padStart(2, '0')).join('')
    let key = cache.get(id)
    if (!key) { key = derivePgpKey(seed, address); cache.set(id, key); key.catch(() => cache.delete(id)) }
    return key
  }
  return {
    async current() {
      const seed = await seeds.current()
      return seed && keyOf(seed)
    },
    async all() {
      const [current, all] = await Promise.all([seeds.current(), seeds.all()])
      const ordered = [...(current ? [current] : []), ...all.filter(seed => !current || !seed.every((byte, index) => byte === current[index]))]
      return Promise.all(ordered.map(keyOf))
    },
  }
}
