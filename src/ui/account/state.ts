// The one owner of the account page's module state. Split out of
// ui/account-page.ts (2026-09-05) when that file was broken up by concern:
// the config object below is read by the account page itself, the config
// page, and the identity modals, so it lives in exactly one place and is
// reached through getAccountConfig() rather than duplicated into each of
// them. `active`/`configPageActive` deliberately did NOT move here -- each
// is read only by the file that owns the page it describes.

export interface AccountPageConfig {
  /** null before any local identity exists yet -- the account page is
   * src.bak's ACTUAL default/landing page for that state too (main.ts's own
   * `if (!sessions.length) showMenuPage('/account')`, and `#new`/`#restore`
   * being retired hashes that just redirect here), not a separate
   * `#new-user-page` overlay. This rewrite had drifted into showing that
   * overlay directly instead (2026-08-25, corrected after user feedback) --
   * `did: null` is what tells showAccountPage() to mount the signup form
   * inline (mountNewUserPageInline) in place of the identity card, matching
   * that design exactly rather than inventing a "default page is the inbox"
   * model this rewrite never actually had. */
  did: string | null
  /** A did.md Wallet account has a public DID, a delegated device capability,
   * and a Biset-owned MLS Vault leaf, but no controller private key.
   * Rendering it here avoids treating it as a zero account. */
  wallet?: {
    handle: string
    deviceJkt: string
    capabilityExpiresAt: string
    /** Set only after Wallet has returned a typed Root+Sign MLS credential
     * for this browser's Biset device leaf. */
    deviceKid?: string
    /** A Biset-owned X25519 DIDComm endpoint authorized and published by
     * Wallet. It has no access to a Wallet controller key. */
    didComm?: { xKid: string; mediatorUrl: string; error?: string }
    /** Starts an explicit, same-tab Wallet approval to add a DIDComm endpoint
     * to an already-connected Biset browser. */
    onEnableMessaging?(): Promise<void>
    onDisconnect(): Promise<void>
  }
  /** Confirmed and invoked by the identity menu's "Log out" item
   * (src.bak/ui/left-pane.ts's confirmAndLogout -- confirm() stays here in
   * the UI layer, this is just the "actually do it" half). */
  onLogout?(): Promise<void>
  /** Live status for the identity's encrypted Vault (MIMI Self Vault --
   * the retired Coordinator backend this card used to also cover is gone).
   * This deliberately contains operational metadata only; no key material
   * belongs in the UI. */
  vault?: VaultCardStatus
  /** Drops one sibling leaf ("zombie device") from the Self/Vault MLS room.
   * MIMI-only (vault.devices only ever has a Remove button rendered when
   * this is set) -- the retired coordinator never had an individual-removal
   * entry point wired to the UI at all. */
  onRemoveVaultDevice?(deviceId: string): Promise<void>
  /** src.bak's showSysMsg (shell.ts) -- injected rather than imported
   * directly: shell.ts -> left-pane.ts -> account-page.ts already, so an
   * import the other way round would close a cycle (main.ts hit the same
   * shape of bug with bootClient itself, 2026-08-25). Used for the DID-copy
   * toast (wireIdentityDid's own "DID copied"). */
  showMessage?(text: string): void
}

export type VaultCardState = 'checking' | 'connecting' | 'syncing' | 'connected' | 'reconnect-required' | 'error'

export interface VaultCardStatus {
  state: VaultCardState
  coordinatorUrl: string
  vaultId?: string
  localSeq?: string
  latestSeq?: string
  checkpointSeq?: string
  detail?: string
  devices?: Array<{ deviceId: string; current: boolean }>
}

let config: AccountPageConfig | undefined

export function configureAccountPage(next: AccountPageConfig): void {
  config = next
}

/** The current config, or undefined before main.ts has configured the page.
 * Callers re-read this at use time (rather than capturing it) wherever the
 * read happens inside a deferred handler, since main.ts can reconfigure the
 * page between render and click. */
export function getAccountConfig(): AccountPageConfig | undefined {
  return config
}
