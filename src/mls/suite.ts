// The one MLS ciphersuite biset speaks, and the one place it is instantiated.
//
// PLANMLS.md picks ts-mls; biset carries a fork of it in `vendor/` (see
// `vendor/VENDOR.md` for why), and this module is the whole of the rest of the
// app's coupling to it — a suite change is a change here and nowhere else.
//
// **MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519** is RFC 9420's
// mandatory-to-implement suite — every conforming implementation speaks it, so
// it is the only choice that can't fail an interop test. It is also the only
// suite ts-mls supports with NO optional peer dependency: the PQ suites
// (X-Wing, ML-KEM) each pull in another `@hpke/*` package, and the app already
// pays ~1MB for ts-mls itself. PLANMLS.md §6 leaves the PQ timing open — when
// it closes, this constant and one `bun add` are the migration.
//
// Note the asymmetry with DIDComm's transport crypto (`didcomm/crypto.ts`),
// which IS PQ-hybrid today (ML-KEM-768 + X25519). That layer protects the
// envelope in transit against harvest-now-decrypt-later; MLS protects the
// group's own key schedule. Different layers, and they may reach PQ at
// different times — see PLANMLS.md §3 on why the two are not alternatives.
import { getCiphersuiteFromName, getCiphersuiteImpl, nobleCryptoProvider, type CiphersuiteImpl, type CiphersuiteName } from './vendor/index.ts'

export const MLS_SUITE: CiphersuiteName = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'

// `nobleCryptoProvider` is the fork's only provider: one set of primitives for
// the whole app rather than WebCrypto here and @noble there, identical in the
// browser, in the anchor (Bun) and in tests, with no SubtleCrypto availability
// caveats — and, less obviously, one FORMAT for a signature private key, which
// the two-provider arrangement upstream did not guarantee (vendor's
// makeNobleSignatureImpl.ts).
let cached: Promise<CiphersuiteImpl> | null = null

/** The ciphersuite implementation, built once per process. */
export function mlsSuite(): Promise<CiphersuiteImpl> {
  // Don't cache a rejection — a transient failure would otherwise poison every
  // later call for the life of the page (same rule as store/idb.ts's db()).
  if (!cached) cached = getCiphersuiteImpl(getCiphersuiteFromName(MLS_SUITE), nobleCryptoProvider).catch(err => { cached = null; throw err })
  return cached
}
