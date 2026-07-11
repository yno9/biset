// Identity-level key genealogy (DID.md "Key genealogy: hybrid, principle (a)").
// One master seed -> deterministic sub-keys, so a single BIP39 backup restores
// the whole identity. Root uses a private SLIP-0010 ed25519 path (no external
// consumer expects a specific path). Nostr uses NIP-06 (registered SLIP-44
// coin type 1237) so the same 24 words re-derive the same npub in any
// NIP-06-compatible Nostr client — the one place a registered path buys real
// interop. PGP stays randomly generated for now (openpgp.js has no supported
// deterministic-seed keygen API); see DID.md's Key genealogy table.
import { ed25519 } from '@noble/curves/ed25519.js'
import { HDKey } from '@scure/bip32'
import { derivePath as slip10DerivePath } from './slip10.ts'
import { zbase32Encode } from './zbase32.ts'

const ROOT_PATH = "m/0'" // private path — signs Pkarr puts, IS the DID
const NOSTR_PATH = "m/44'/1237'/0'/0/0" // NIP-06

export interface KeyPair { publicKey: Uint8Array; privateKey: Uint8Array }

export function deriveRootKey(masterSeed: Uint8Array): KeyPair {
  const node = slip10DerivePath(masterSeed, ROOT_PATH)
  return { privateKey: node.key, publicKey: ed25519.getPublicKey(node.key) }
}

export function deriveNostrKey(masterSeed: Uint8Array): KeyPair {
  const child = HDKey.fromMasterSeed(masterSeed).derive(NOSTR_PATH)
  if (!child.privateKey || !child.publicKey) throw new Error('Nostr key derivation failed')
  // secp256k1 x-only pubkey (BIP340/Nostr) drops the leading parity byte.
  return { privateKey: child.privateKey, publicKey: child.publicKey.slice(1) }
}

export function didFromRootPublicKey(rootPublicKey: Uint8Array): string {
  return `did:dht:${zbase32Encode(rootPublicKey)}`
}
