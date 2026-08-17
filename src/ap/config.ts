// ActivityPub is retired (2026-08-16 — jmapap taken down, unused: no
// followers/DMs from the fediverse ever came through it). Every call site
// that would REACH OUT to an AP relay (resolve/webfinger, avatar upload,
// account provisioning) gates through apOutboundUrl() below, which this one
// flag controls — flip it back to `true` and every one of those call sites
// resumes working with no other changes anywhere in the app.
//
// This does NOT affect isApRelay (context.ts) or anything that only reads
// data already on disk (an existing AP-relay session/account, a stored
// contact's protocol) — those keep working regardless, so nothing already
// stored silently misrenders just because outbound AP is off.
const AP_ENABLED = false

/** The AP relay base URL to actually use for a NEW outbound call (resolve,
 * avatar advertise, account provisioning) — '' whenever AP_ENABLED is off,
 * regardless of what config.json says, so turning AP off here is the one
 * place that needs to change. Same domain-convention fallback every call
 * site used to inline (`cfg.ap_url || https://ap.<hostname>`). */
export function apOutboundUrl(cfg: { ap_url?: string; hostname?: string } | undefined | null): string {
  if (!AP_ENABLED) return ''
  return cfg?.ap_url || (cfg?.hostname ? `https://ap.${cfg.hostname}` : '')
}
