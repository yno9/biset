// The identity master seed is the SAME 32 random bytes cryptenv.ts already
// generates as `masterSecret` (see cryptenv.ts's HKDF diagram) — no new secret
// is introduced. entropyToMnemonic/mnemonicToEntropy is a reversible encoding
// (no PBKDF2 stretching), so the 24-word BIP39 mnemonic IS the master secret,
// just human-writable. This is what buys "one paper backup restores everything"
// (DID.md's Key genealogy) without touching the envelope format.
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'

export function seedToMnemonic(masterSecret: Uint8Array): string {
  if (masterSecret.length !== 32) throw new Error('master seed must be 32 bytes')
  return entropyToMnemonic(masterSecret, wordlist)
}

export function mnemonicToSeed(mnemonic: string): Uint8Array {
  return mnemonicToEntropy(mnemonic.trim().toLowerCase(), wordlist)
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic.trim().toLowerCase(), wordlist)
}
