// Identity-level key derivation: one BIP39 master seed -> a deterministic
// root Ed25519 keypair via SLIP-0010, so a single 24-word phrase (seed.ts)
// restores the whole identity. Ported from src.bak/did/keys.ts, trimmed to
// just the root key — the per-device DIDComm/ML-KEM derivations there are a
// DIDComm-adapter concern this rewrite does not carry forward yet
// (PLAN.md §6.1's still-open DIDComm adapter), and this device's own MLS
// leaf key is independently generated (mls/group.ts's generateOwnKeyPackage),
// never seed-derived — see PLANMLSDIDCRED.md §2.3's "no new key type" stance:
// the leaf key IS the device's control key, so there is nothing here for it
// to derive from the seed in the first place.
import { ed25519 } from '@noble/curves/ed25519.js'
import { derivePath } from './slip10.ts'

const ROOT_PATH = "m/0'" // private path -- signs updateKeys authority, IS the DID's root key

export interface KeyPair { publicKey: Uint8Array; privateKey: Uint8Array }

export function deriveRootKey(masterSeed: Uint8Array): KeyPair {
  const node = derivePath(masterSeed, ROOT_PATH)
  return { privateKey: node.key, publicKey: ed25519.getPublicKey(node.key) }
}
