// Single source for reading window.__BISET_CONFIG__ -- account-create.ts and
// main.ts each need apexDomain/coreBaseUrl, so this is read in one place
// rather than two copies of the same window-global reach-through drifting
// apart.
declare const __BISET_CONFIG__: { apexDomain?: string; anchorBaseUrl?: string; anchorOidcClientId?: string; coreBaseUrl?: string; mediatorUrls?: string[]; mimiSelfBaseUrl?: string; conversationMlsDsBaseUrl?: string } | undefined

export interface BisetConfig {
  apexDomain: string
  /** Public identity-provider endpoint. Empty while the legacy Core
   * compatibility mount remains authoritative. */
  anchorBaseUrl: string
  /** Static public-client registration at Anchor. */
  anchorOidcClientId: string
  coreBaseUrl: string
  /** Independent, blind DIDComm mediators this deployment registers new
   * identities with (ARC.md's 2026-08-27 redesign, identity/bootstrap.ts's
   * `enableDidComm`) -- empty/unset keeps the legacy direct-delivery model
   * exactly as before (no mediator involved at all). Additive and opt-in on
   * purpose: production currently opts into https://mediator.biset.md. */
  mediatorUrls: string[]
  /** Dedicated normal-mode MIMI endpoint for the owner's Self/Vault room. */
  mimiSelfBaseUrl: string
  /** Optional: this deployment's Conversation Group MLS Delivery Service
   * (mls-ds/http.ts). Empty disables CREATING a new Conversation Group from
   * this device (main.ts) -- receiving an invite into, and participating
   * in, a group someone else created needs no local config at all, since
   * that group's own DS URL is learned from the invite (resolved via
   * `resolveMimiProviderUrl`) or, after the first join, from this device's
   * own `conversation-group-store.ts` row. */
  conversationMlsDsBaseUrl: string
}

export function readBisetConfig(): BisetConfig {
  const cfg = (window as unknown as { __BISET_CONFIG__?: typeof __BISET_CONFIG__ }).__BISET_CONFIG__ ?? {}
  return {
    apexDomain: cfg.apexDomain ?? '',
    anchorBaseUrl: cfg.anchorBaseUrl ?? '',
    anchorOidcClientId: cfg.anchorOidcClientId ?? '',
    coreBaseUrl: cfg.coreBaseUrl ?? '',
    mediatorUrls: cfg.mediatorUrls ?? [],
    mimiSelfBaseUrl: cfg.mimiSelfBaseUrl ?? '',
    conversationMlsDsBaseUrl: cfg.conversationMlsDsBaseUrl ?? '',
  }
}
