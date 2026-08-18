export * from './seed.ts'
export * from './keys.ts'
export * from './store.ts'
export * from './resolver.ts'
export * from './document.ts'

import { deriveRootKey, deriveNostrKey } from './keys.ts'
import { getDidRecord, storeDidRecord, type DidRecord } from './store.ts'
import { createGenesis, type BisetRelay } from './webvh/publish.ts'

const toHex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

// The seed-derives-nothing-but-keys half of identity creation: a did:webvh
// identifier can't be recomputed from the seed alone (webvh/publish.ts's SCID
// depends on genesis TIME, not just the root key), so callers that already
// know the DID string — a recovery-phrase restore (restore.ts), resolved and
// verified against the seed's root key by the caller — arrive here to attach
// it to a local record rather than deriving it. Idempotent: reuses the stored
// record if this seed already has one for this exact DID.
//
// Does NOT touch the DIDComm (_k1) key — that's a per-DEVICE concern now, not
// a per-IDENTITY one (document.ts's DidKeyAgreement note), so it's minted
// lazily by didcomm-devices.ts the first time THIS device registers with a
// mediator, never derived here from the seed.
export async function localDidRecord(masterSeed: Uint8Array, did: string, email?: string): Promise<DidRecord> {
  const existing = await getDidRecord(did)
  if (existing) {
    // Backfill masterSeed onto a record that predates this being stored at
    // all (2026-08-17 — see this field's own note below) — otherwise a
    // pre-existing identity's Root Key phrase can NEVER be re-shown on this
    // device, ever, even after typing the correct phrase back in here,
    // since this early-return used to skip straight past the write below.
    // Verified against rootPrivateKey FIRST: a wrong phrase (typo, someone
    // else's identity) must never silently attach a seed that doesn't
    // actually belong to this record.
    if (!existing.masterSeed) {
      const candidateRoot = deriveRootKey(masterSeed)
      if (toHex(candidateRoot.privateKey) === existing.rootPrivateKey) {
        const updated: DidRecord = { ...existing, masterSeed: toHex(masterSeed) }
        await storeDidRecord(updated)
        return updated
      }
    }
    return existing
  }

  const root = deriveRootKey(masterSeed)
  const nostr = deriveNostrKey(masterSeed)
  const record: DidRecord = {
    did,
    ...(email ? { email } : {}),
    // Stored so a LATER action needing the seed (claimMailAccount's PGP
    // setup via deriveKek, showStoredMnemonic's re-display) has it without
    // requiring a fresh phrase entry — rootPrivateKey is deriveRootKey's
    // one-way SLIP-10 output and cannot be reversed back into this. Without
    // it, the seed was only ever in scope at the exact moment a phrase was
    // typed in, nowhere else (found live, 2026-08-17: a relay claimed long
    // after restore had no PGP key, silently, because initPGPForSession
    // needs a kek derived from this exact seed and none was ever kept).
    masterSeed: toHex(masterSeed),
    rootPublicKey: toHex(root.publicKey),
    rootPrivateKey: toHex(root.privateKey),
    nostrPublicKey: toHex(nostr.publicKey),
    nostrPrivateKey: toHex(nostr.privateKey),
  }
  await storeDidRecord(record)
  return record
}

// did:webvh identity creation (PLANWEBVH.md §4). This can NOT be a pure
// function of the seed alone: the SCID depends on the whole genesis
// document's content, not just the root public key (webvh/scid.ts's note), so
// a did:webvh identity doesn't exist until it has actually been published.
// This is a network call, not an offline derivation — and, per PLANWEBVH.md
// §2.1, the seed alone cannot recreate this DID if the local record is ever
// lost (SCID persistence lives in the anchor, not here).
//
// `domain`/`username` select biset's path-segment identifier
// (PLANWEBVH.md §2.3): did:webvh:{scid}:{domain}:{username} — the fix
// for biset.md/t.biset.md's apex-sharing problem.
export async function initDidWebvh(
  masterSeed: Uint8Array,
  opts: { domain: string; username: string; relays: BisetRelay[]; addresses: string | string[]; email?: string },
): Promise<DidRecord> {
  const root = deriveRootKey(masterSeed)
  const { did } = await createGenesis({
    domain: opts.domain, username: opts.username,
    rootPrivateKey: root.privateKey, rootPublicKey: root.publicKey,
    relays: opts.relays, addresses: opts.addresses,
  })

  const existing = await getDidRecord(did)
  if (existing) return existing

  const nostr = deriveNostrKey(masterSeed)
  const record: DidRecord = {
    did,
    ...(opts.email ? { email: opts.email } : {}),
    // See localDidRecord's own note just above — same reasoning, same fix.
    masterSeed: toHex(masterSeed),
    rootPublicKey: toHex(root.publicKey),
    rootPrivateKey: toHex(root.privateKey),
    nostrPublicKey: toHex(nostr.publicKey),
    nostrPrivateKey: toHex(nostr.privateKey),
  }
  await storeDidRecord(record)
  return record
}

// One-off did:webvh → did:webvh path-shape migration (2026-08-12): drops the
// `dids/` path segment (did:webvh:{scid}:{domain}:dids:{username} →
// :{domain}:{username}) for the one real account still on the old shape,
// y@biset.md. A NEW genesis (new SCID), not a rename — did:webvh's SCID is
// derived from the whole genesis document, not the path, so there is no way
// to keep the old SCID under a new path. Reuses the same root/nostr keys
// (method-independent key material) and the device's own JMAP login
// credential, same reasoning as migrateDhtToWebvh (removed after y's
// did:dht→did:webvh migration completed) — see that function's own note,
// since this is its direct descendant.
export async function migrateWebvhPathShape(
  oldDid: string,
  opts: { domain: string; username: string },
): Promise<DidRecord> {
  const old = await getDidRecord(oldDid)
  if (!old) throw new Error(`migrateWebvhPathShape: no local record for ${oldDid}`)
  const { hexToBytes } = await import('../utils.ts')
  const { did } = await createGenesis({
    domain: opts.domain,
    username: opts.username,
    rootPrivateKey: hexToBytes(old.rootPrivateKey),
    rootPublicKey: hexToBytes(old.rootPublicKey),
    relays: [],
    addresses: [],
  })

  const existing = await getDidRecord(did)
  if (existing) return existing

  const record: DidRecord = {
    did,
    ...(old.email ? { email: old.email } : {}),
    rootPublicKey: old.rootPublicKey,
    rootPrivateKey: old.rootPrivateKey,
    nostrPublicKey: old.nostrPublicKey,
    nostrPrivateKey: old.nostrPrivateKey,
    ...(old.masterSeed ? { masterSeed: old.masterSeed } : {}),
    ...(old.envelope ? { envelope: old.envelope } : {}),
    ...(old.jmapDevicePublicKey ? { jmapDevicePublicKey: old.jmapDevicePublicKey } : {}),
    ...(old.jmapDevicePrivateKey ? { jmapDevicePrivateKey: old.jmapDevicePrivateKey } : {}),
  }
  await storeDidRecord(record)
  return record
}
