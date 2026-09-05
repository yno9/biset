// biset: the one crypto provider. Everything it returns is built on the
// @noble packages the app already bundles; the WebCrypto ("default") provider
// upstream shipped alongside it is deleted.
import { Ciphersuite, CiphersuiteImpl } from "../../ciphersuite.js"
import { CryptoProvider } from "../../provider.js"
import { makeHashImpl } from "./makeHashImpl.js"
import { makeNobleSignatureImpl } from "./makeNobleSignatureImpl.js"
import { makeHpke } from "./hpke.js"
import { makeKdfImpl } from "./makeKdfImpl.js"
import { defaultRng } from "./rng.js"

/** @public */
export const nobleCryptoProvider: CryptoProvider = {
  async getCiphersuiteImpl(cs: Ciphersuite): Promise<CiphersuiteImpl> {
    return {
      kdf: makeKdfImpl(),
      hash: makeHashImpl(),
      signature: await makeNobleSignatureImpl(),
      hpke: makeHpke(cs.hpke),
      rng: defaultRng,
      name: cs.name,
    }
  },
}
