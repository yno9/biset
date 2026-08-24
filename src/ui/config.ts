// Single source for reading window.__BISET_CONFIG__ -- account-create.ts and
// main.ts each need apexDomain/coreBaseUrl, so this is read in one place
// rather than two copies of the same window-global reach-through drifting
// apart.
declare const __BISET_CONFIG__: { apexDomain?: string; coreBaseUrl?: string } | undefined

export interface BisetConfig {
  apexDomain: string
  coreBaseUrl: string
}

export function readBisetConfig(): BisetConfig {
  const cfg = (window as unknown as { __BISET_CONFIG__?: typeof __BISET_CONFIG__ }).__BISET_CONFIG__ ?? {}
  return { apexDomain: cfg.apexDomain ?? '', coreBaseUrl: cfg.coreBaseUrl ?? '' }
}
