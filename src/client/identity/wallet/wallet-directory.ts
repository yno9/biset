/**
 * PLAN4 (~/did.md/PLAN4-wallet-connector.md): the "connect with [...]" wallet
 * button abstraction. biset accepts any wallet that speaks the did.md
 * protocol family (SIOPv2/OID4VP-shaped, see ~/did.md/SPEC.md §5) -- did-md-
 * oauth.ts is not dito-specific code that happens to also work elsewhere;
 * it is the OAuth/OID4VP client, and dito is one entry in this directory,
 * not a hardcoded assumption. DC API and CHAPI were both evaluated and
 * rejected as the selector mechanism (SPEC.md §4.4); this static,
 * bundled list is the deliberately unglamorous v1 substitute (SPEC.md §5.5).
 *
 * Distribution format (SPEC.md §8's open question, now decided for v1):
 * a static array bundled with the client. No registry server, no dynamic
 * fetch -- see PLAN4's non-scope. Growing this beyond a bundled array
 * (a hosted registry, user-supplied URLs) is future work, not this list.
 */
export type WalletDirectoryEntry = {
  /** Stable local identifier, never sent over the wire. */
  id: string
  /** Shown in the wallet-picker UI. */
  displayName: string
  /** The OAuth/OID4VP issuer identifier (RFC 8414) -- the base origin
   * .well-known/oauth-authorization-server is discovered from. */
  issuer: string
  /** Suffix a handle typed into the login form must end with, for this
   * wallet's own hosting convention (e.g. ".did.md"). Purely a UI input
   * hint -- the actual trust check is DID resolution, not this string. */
  handleSuffix: string
}

// v1 lists dito as the one entry this directory ships with. It is not
// special-cased anywhere in did-md-oauth.ts beyond being index 0 here --
// see PLAN4's verification task for the standard this is held to.
export const WALLET_DIRECTORY: readonly WalletDirectoryEntry[] = [
  { id: 'dito', displayName: 'dito (did.md)', issuer: 'https://api.did.md', handleSuffix: '.did.md' },
]

export const DEFAULT_WALLET: WalletDirectoryEntry = WALLET_DIRECTORY[0]!
