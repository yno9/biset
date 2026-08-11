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

/** What a claim holds. **Only the DID** — the DID is the identity anchor, so a
 * second one was one too many.
 *
 * It used to carry the envelope fingerprint, which predates DIDs and which
 * nothing ever read: `claim()` compared it only against itself. Its whole job
 * was spotting two DID-less accounts of the same name diverging, and a DID-less
 * account publishes nothing — no DNS record, no document — so the split it
 * detected was two strangers who happen to share a name, which is not a
 * problem. Meanwhile it cost: a squatted fingerprint locked the real owner out
 * of their own name forever, since every later claim of theirs carried their
 * real one and 409'd.
 *
 * It also never guarded what it looked like it guarded. Provisioning claims with
 * `fp=""`, so the fingerprint check simply never fired there. */
export interface AnchorRecord {
  did: string
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
      // Everything under dataDir that is not an address domain is prefixed with
      // an underscore, and a real domain cannot be (`_did`, the Go service's
      // derived copy, which is never read; `_pkarr`, the gateway's republish
      // set). Skipping them by name rather than by shape: `_pkarr` happens to
      // hold files, so subdirs() would return nothing for it today and the loop
      // would be harmless — but that is an accident, not a guarantee, and a
      // future internal directory holding subdirectories would quietly be
      // scanned as somebody's domain.
      if (domain.startsWith('_')) continue
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

  /** A claim, or null when there is nothing worth reading — which now includes
   * every file that only ever held a fingerprint. Those exist on disk (two in
   * production) and are inert: with no DID they claim nothing, and the index
   * already ignored them. They are left alone rather than deleted; the next
   * genuine claim for that name overwrites them. */
  read(domain: string, localpart: string): AnchorRecord | null {
    let s: string
    try {
      s = readFileSync(identityFPPath(this.dataDir, domain, localpart), 'utf-8').trim()
    } catch {
      return null
    }
    // A bare hex string is the pre-DID jmapap format: a fingerprint, nothing
    // else. Nothing to read out of it any more.
    if (s === '' || s[0] !== '{') return null
    try {
      const rec = JSON.parse(s) as { did?: string }
      return rec.did ? { did: rec.did } : null
    } catch {
      return null
    }
  }

  /** The file keeps its `identity.fp` name. It is vestigial — there is no
   * fingerprint in it — but renaming it means migrating live data for a word,
   * and the path is not what anyone reads. */
  private write(domain: string, localpart: string, rec: AnchorRecord): boolean {
    const path = identityFPPath(this.dataDir, domain, localpart)
    try {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
      writeFileSync(path, JSON.stringify({ did: rec.did }), { mode: 0o600 })
    } catch {
      return false
    }
    this.link(rec.did, domain, localpart)
    return true
  }

  /** Records which DID owns a name, or verifies an existing claim against it.
   * Returns false only on a genuine conflict: the name is already held by a
   * DIFFERENT DID. Root keys are rotation-less by design, so a mismatch is a bug
   * or a split attempt, never a legitimate update.
   *
   * There is nothing else to claim by. A claim with no DID would record nothing
   * and mean nothing — an account without a DID publishes no DNS record and no
   * document, so no name it holds needs defending here. */
  claim(domain: string, localpart: string, did: string): boolean {
    if (did === '') return false
    const existing = this.read(domain, localpart)
    if (!existing) return this.write(domain, localpart, { did })
    if (existing.did !== did) return false
    // Idempotent: nothing on disk changes. The index still needs to know about
    // this DID — under the Go service this early return is exactly where the
    // index silently failed to heal.
    this.link(did, domain, localpart)
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
