// Identity anchor storage — the claim registry. Ported from go-didanchor's
// anchor.go (ANCHOR.md decision 5: staged migration, step 1 is "same behavior,
// same files, different language"), so this reads and writes **the same
// `identity.fp` layout** the deployed Go service uses. That is the point: no
// data migration, and both can run against the same directory during cutover.
//
//   <dataDir>/<domain>/<localpart>/identity.fp   {"fingerprint":"…","did":"…"}
//
// Storage is keyed by the REAL address domain the caller passes — an earlier
// version inside jmapap silently bucketed every caller under jmapap's own
// primaryDomain() regardless of the account's actual domain (harmless with one
// domain, wrong once t.biset.md existed).
//
// **DID→address is derived, never stored** (ANCHOR.md, 2026-07-16). The Go
// service keeps a second copy on disk at `<dataDir>/_did/<did>`, and that copy
// had silently drifted out of sync in production: `biset.md/y` — a real, live
// account — had a DID but no index entry, so `by-did` 404'd for it while the
// forward lookup worked fine. Cause, from reading the Go source: the index is
// only written by writeAnchorRecord, and claimIdentity's idempotent path (both
// fields already present and matching) returns early **without writing**, so a
// once-missing entry can never come back. It went missing in the v1→v2 move
// and no amount of re-claiming would have rebuilt it. The index is a pure
// function of the identity.fp files, so keeping a separate copy bought nothing
// and cost correctness — this builds it at startup instead. The stale `_did/`
// files on disk are simply never read; they can be deleted once the Go service
// is retired.
import { mkdirSync, readFileSync, readdirSync, writeFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'

export interface AnchorRecord {
  fingerprint: string
  /** omitted from JSON when empty, matching Go's `json:"did,omitempty"` */
  did?: string
}

const identityFPPath = (dataDir: string, domain: string, localpart: string) =>
  join(dataDir, domain, localpart, 'identity.fp')

export interface DidLocation { domain: string; localpart: string }

export class ClaimStore {
  /** DID → every address it holds. Derived from disk at startup and maintained
   * here; the identity.fp files remain the only source of truth.
   *
   * A list, not a single location: one identity legitimately holds several
   * addresses — mail and AP, or the old and new one across a move — and the
   * whole point of a cross-relay index is to answer with all of them. Keying it
   * 1:1 (as this did while it only mirrored go-didanchor) makes the last address
   * scanned silently evict the others. Production has no such DID today, so
   * nothing is being repaired here; it would simply have lost the answer the
   * first time one appeared. */
  private byDid = new Map<string, DidLocation[]>()

  constructor(private dataDir: string) {
    this.rebuildIndex()
  }

  /** Scans every `<domain>/<localpart>/identity.fp` and rebuilds the DID index.
   * Cheap: one small file per account (production holds single digits, and even
   * a large deployment is thousands of stat+reads at boot, once). */
  rebuildIndex(): number {
    this.byDid.clear()
    for (const domain of this.subdirs(this.dataDir)) {
      if (domain === '_did') continue // the Go service's derived copy — never read
      for (const localpart of this.subdirs(join(this.dataDir, domain))) {
        const rec = this.read(domain, localpart)
        if (rec?.did) this.link(rec.did, domain, localpart)
      }
    }
    return this.byDid.size
  }

  /** Adds an address to a DID's list, idempotently — re-claiming an identity
   * must not list its address twice. */
  private link(did: string, domain: string, localpart: string): void {
    const at = this.byDid.get(did)
    if (!at) { this.byDid.set(did, [{ domain, localpart }]); return }
    if (!at.some(l => l.domain === domain && l.localpart === localpart)) at.push({ domain, localpart })
  }

  /** Drops one address from a DID's list, forgetting the DID entirely once its
   * last address is gone (so by-did 404s rather than answering with []). */
  private unlink(did: string, domain: string, localpart: string): void {
    const at = this.byDid.get(did)
    if (!at) return
    const rest = at.filter(l => !(l.domain === domain && l.localpart === localpart))
    if (rest.length === 0) this.byDid.delete(did)
    else this.byDid.set(did, rest)
  }

  /** Every address this DID holds, across every domain the anchor serves —
   * empty if it holds none. */
  lookupByDid(did: string): DidLocation[] {
    return this.byDid.get(did) ?? []
  }

  private subdirs(dir: string): string[] {
    try {
      return readdirSync(dir, { withFileTypes: true }).filter(e => e.isDirectory()).map(e => e.name)
    } catch {
      return []
    }
  }

  read(domain: string, localpart: string): AnchorRecord | null {
    let s: string
    try {
      s = readFileSync(identityFPPath(this.dataDir, domain, localpart), 'utf-8').trim()
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

  private write(domain: string, localpart: string, rec: AnchorRecord): boolean {
    const path = identityFPPath(this.dataDir, domain, localpart)
    try {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
      // Match Go's json.Marshal of `did,omitempty`: an empty DID is absent, not null.
      const body = rec.did ? { fingerprint: rec.fingerprint, did: rec.did } : { fingerprint: rec.fingerprint }
      writeFileSync(path, JSON.stringify(body), { mode: 0o600 })
    } catch {
      return false
    }
    if (rec.did) this.link(rec.did, domain, localpart)
    return true
  }

  /** Records the fingerprint (and, once known, the DID) for a name, or verifies
   * it against an existing claim. Returns false only on a genuine conflict —
   * name already held by a different fingerprint, or a DID mismatch against an
   * already-registered DID for this name (root keys are rotation-less by
   * design, so a mismatch signals a bug or a split attempt, never a legitimate
   * update). fp/did may be '' (not yet known) — an empty value never conflicts,
   * it just skips that field. First claim and idempotent re-claims return true. */
  claim(domain: string, localpart: string, fp: string, did: string): boolean {
    if (fp === '' && did === '') return false // nothing to claim by
    const existing = this.read(domain, localpart)
    if (!existing) return this.write(domain, localpart, { fingerprint: fp, did })
    if (fp !== '' && existing.fingerprint !== '' && existing.fingerprint !== fp) return false
    if (did !== '' && existing.did && existing.did !== did) return false
    if ((did !== '' && !existing.did) || (fp !== '' && existing.fingerprint === '')) {
      return this.write(domain, localpart, {
        fingerprint: existing.fingerprint || fp,
        did: existing.did || did,
      })
    }
    // Idempotent: nothing on disk changes. The index still needs to know about
    // this DID — under the Go service this early return is exactly where the
    // index silently failed to heal.
    if (existing.did) this.link(existing.did, domain, localpart)
    return true
  }

  /** Forgets a claim entirely — call when the underlying account is permanently
   * deleted, so the address becomes claimable again (by anyone, including its
   * original owner under a fresh identity). Without this, claim() would keep
   * rejecting a legitimate future registration of the same address as a false
   * "different key" conflict forever. Removing what's already gone is not an
   * error — release is idempotent. */
  release(domain: string, localpart: string): void {
    const existing = this.read(domain, localpart)
    rmSync(identityFPPath(this.dataDir, domain, localpart), { force: true })
    // Only this address leaves the DID's list. Deleting the whole entry would
    // unpublish an identity's remaining addresses because one of them was
    // released.
    if (existing?.did) this.unlink(existing.did, domain, localpart)
  }

}
