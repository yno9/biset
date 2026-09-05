import { Ciphersuite, CiphersuiteImpl } from "./ciphersuite.js"
import { CryptoProvider } from "./provider.js"
// biset: the WebCrypto ("default") provider is deleted — one provider, built
// on the @noble packages biset already bundles, so there is no second set of
// primitives that could disagree with the first.
import { nobleCryptoProvider } from "./implementation/noble/provider.js"

/** @public */
export async function getCiphersuiteImpl(
  cs: Ciphersuite,
  provider: CryptoProvider = nobleCryptoProvider,
): Promise<CiphersuiteImpl> {
  return provider.getCiphersuiteImpl(cs)
}
