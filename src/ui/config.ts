// Single source for reading window.__BISET_CONFIG__ -- account-create.ts and
// main.ts each need apexDomain/coreBaseUrl, so this is read in one place
// rather than two copies of the same window-global reach-through drifting
// apart.
declare const __BISET_CONFIG__: { apexDomain?: string; coreBaseUrl?: string; mediatorUrls?: string[] } | undefined

export interface BisetConfig {
  apexDomain: string
  coreBaseUrl: string
  /** Independent, blind DIDComm mediators this deployment registers new
   * identities with (ARC.md's 2026-08-27 redesign, identity/bootstrap.ts's
   * `enableDidComm`) -- empty/unset keeps the legacy direct-delivery model
   * exactly as before (no mediator involved at all). Additive and opt-in on
   * purpose: nothing sets this today, since no standalone mediator is
   * deployed yet. */
  mediatorUrls: string[]
}

export function readBisetConfig(): BisetConfig {
  const cfg = (window as unknown as { __BISET_CONFIG__?: typeof __BISET_CONFIG__ }).__BISET_CONFIG__ ?? {}
  return { apexDomain: cfg.apexDomain ?? '', coreBaseUrl: cfg.coreBaseUrl ?? '', mediatorUrls: cfg.mediatorUrls ?? [] }
}
