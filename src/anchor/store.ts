// Identity anchor storage — the claim registry. Ported from go-didanchor's
// anchor.go (ANCHOR.md decision 5: staged migration, step 1 is "same behavior,
// same files, different language"), so this reads and writes **the exact same
// on-disk layout** the deployed Go service uses. That is the whole point: no
// data migration, and both can run against the same directory during cutover.
//
//   <dataDir>/<domain>/<localpart>/identity.fp   {"fingerprint":"…","did":"…"}
//   <dataDir>/_did/<did>                          "<domain>/<localpart>"
//
// Storage is keyed by the REAL address domain the caller passes — an earlier
// version inside jmapap silently bucketed every caller under jmapap's own
// primaryDomain() regardless of the account's actual domain (harmless with one
// domain, wrong once t.biset.md existed).
import { mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'

export interface AnchorRecord {
  fingerprint: string
  /** omitted from JSON when empty, matching Go's `json:"did,omitempty"` */
  did?: string
}

const identityFPPath = (dataDir: string, domain: string, localpart: string) =>
  join(dataDir, domain, localpart, 'identity.fp')

/** A DID maps back to its (domain, localpart) here. Keyed on the DID string
 * itself (already URL-safe z-base-32) since a DID is domain-independent. */
const didIndexPath = (dataDir: string, did: string) => join(dataDir, '_did', did)

export function readAnchorRecord(dataDir: string, domain: string, localpart: string): AnchorRecord | null {
  let s: string
  try {
    s = readFileSync(identityFPPath(dataDir, domain, localpart), 'utf-8').trim()
  } catch {
    return null
  }
  if (s === '') return null
  if (s[0] === '{') {
    try {
      return JSON.parse(s) as AnchorRecord
    } catch {
      return null
    }
  }
  // Legacy format inherited from pre-DID jmapap: the file held the bare
  // fingerprint hex string. Still on disk for old accounts — do not drop this.
  return { fingerprint: s }
}

function writeAnchorRecord(dataDir: string, domain: string, localpart: string, rec: AnchorRecord): boolean {
  const path = identityFPPath(dataDir, domain, localpart)
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    // Match Go's json.Marshal of `did,omitempty`: an empty DID is absent, not null.
    const body = rec.did ? { fingerprint: rec.fingerprint, did: rec.did } : { fingerprint: rec.fingerprint }
    writeFileSync(path, JSON.stringify(body), { mode: 0o600 })
  } catch {
    return false
  }
  if (rec.did) {
    try {
      const didPath = didIndexPath(dataDir, rec.did)
      mkdirSync(dirname(didPath), { recursive: true, mode: 0o700 })
      writeFileSync(didPath, `${domain}/${localpart}`, { mode: 0o600 })
    } catch {
      // Go ignores this error too: the forward claim is what matters, the
      // reverse index is a lookup convenience that can be rebuilt.
    }
  }
  return true
}

/** Records the fingerprint (and, once known, the DID) for a name, or verifies
 * it against an existing claim. Returns false only on a genuine conflict —
 * name already held by a different fingerprint, or a DID mismatch against an
 * already-registered DID for this name (root keys are rotation-less by design,
 * so a mismatch signals a bug or a split attempt, never a legitimate update).
 * fp/did may be '' (not yet known) — an empty value never conflicts, it just
 * skips that field. First claim and idempotent re-claims return true. */
export function claimIdentity(dataDir: string, domain: string, localpart: string, fp: string, did: string): boolean {
  if (fp === '' && did === '') return false // nothing to claim by
  const existing = readAnchorRecord(dataDir, domain, localpart)
  if (!existing) return writeAnchorRecord(dataDir, domain, localpart, { fingerprint: fp, did })
  if (fp !== '' && existing.fingerprint !== '' && existing.fingerprint !== fp) return false
  if (did !== '' && existing.did && existing.did !== did) return false
  if ((did !== '' && !existing.did) || (fp !== '' && existing.fingerprint === '')) {
    return writeAnchorRecord(dataDir, domain, localpart, {
      fingerprint: existing.fingerprint || fp,
      did: existing.did || did,
    })
  }
  return true
}

/** Forgets a claim entirely — call when the underlying account is permanently
 * deleted, so the address becomes claimable again (by anyone, including its
 * original owner under a fresh identity). Without this, claimIdentity would
 * keep rejecting a legitimate future registration of the same address as a
 * false "different key" conflict forever. Removing what's already gone is not
 * an error — release is idempotent. */
export function releaseIdentity(dataDir: string, domain: string, localpart: string): void {
  const existing = readAnchorRecord(dataDir, domain, localpart)
  rmSync(identityFPPath(dataDir, domain, localpart), { force: true })
  if (existing?.did) rmSync(didIndexPath(dataDir, existing.did), { force: true })
}

/** Which (domain, localpart) a DID belongs to, via the reverse index written
 * alongside every claim that carries a DID. */
export function resolveDID(dataDir: string, did: string): { domain: string; localpart: string } | null {
  let s: string
  try {
    s = readFileSync(didIndexPath(dataDir, did), 'utf-8').trim()
  } catch {
    return null
  }
  const i = s.indexOf('/')
  if (i < 0) return null
  return { domain: s.slice(0, i), localpart: s.slice(i + 1) }
}
