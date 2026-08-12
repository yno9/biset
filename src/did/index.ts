export * from './seed.ts'
export * from './keys.ts'
export * from './store.ts'
export * from './resolver.ts'
export { didFromRootPublicKey, deriveContinuationKey } from './dht/identifier.ts'
export { buildBisetDocument, documentToRecords, recordsToDocument } from './dht/document.ts'
export { buildSignedPayload, parseSignedPayload, nowSeq } from './dht/packet.ts'
export { seenSeq, noteSeq } from './dht/freshness.ts'

import { deriveRootKey, deriveNostrKey } from './keys.ts'
import { didFromRootPublicKey } from './dht/identifier.ts'
import { getDidRecord, storeDidRecord, type DidRecord } from './store.ts'
import { createGenesis, type BisetRelay } from './webvh/publish.ts'

const toHex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

// Ensures this seed has a locally-derived DID identity, deriving it on first
// call (creation, or first login after rollout for existing accounts —
// DID.md's "lazy migration") and reusing the stored record on every
// subsequent call (reload, or an identity that already exists) — same
// pattern as PGP's initPGP()/getKeyRecord() early-return.
//
// did is the essential key here, not email: the DID is computable from the
// seed alone, so it's derived FIRST and used to look up/store the record —
// an identity with no mail/AP address yet works exactly the same way as one
// that has several (mail/AP is an optional add-on a DidRecord may carry,
// never what it's keyed by — see store.ts's file header). `email`, when
// given, is only ever recorded as informational metadata on the record.
//
// Does NOT touch the DIDComm (_k1) key — that's a per-DEVICE concern now, not
// a per-IDENTITY one (document.ts's DidKeyAgreement note), so it's minted
// lazily by didcomm-devices.ts the first time THIS device registers with a
// mediator, never derived here from the seed.
export async function initDid(masterSeed: Uint8Array, email?: string): Promise<DidRecord> {
  const root = deriveRootKey(masterSeed)
  return localDidRecord(masterSeed, didFromRootPublicKey(root.publicKey), email)
}

// The did-already-known half of initDid, split out for restore.ts's did:webvh
// path: unlike did:dht, a did:webvh identifier can't be recomputed from the
// seed alone (webvh/publish.ts's SCID depends on genesis TIME, not just the
// root key), so a recovery-phrase restore of one arrives already holding the
// DID string (resolved + verified against the seed's root key by the
// caller) rather than deriving it here. Same idempotent shape either way:
// reuse the stored record if this seed already has one for this exact DID.
export async function localDidRecord(masterSeed: Uint8Array, did: string, email?: string): Promise<DidRecord> {
  const existing = await getDidRecord(did)
  if (existing) return existing

  const root = deriveRootKey(masterSeed)
  const nostr = deriveNostrKey(masterSeed)
  const record: DidRecord = {
    did,
    ...(email ? { email } : {}),
    rootPublicKey: toHex(root.publicKey),
    rootPrivateKey: toHex(root.privateKey),
    nostrPublicKey: toHex(nostr.publicKey),
    nostrPrivateKey: toHex(nostr.privateKey),
  }
  await storeDidRecord(record)
  return record
}

// did:webvh identity creation (PLANWEBVH.md §4). Unlike initDid() (did:dht),
// this can NOT be a pure function of the seed alone: the SCID depends on the
// whole genesis document's content, not just the root public key
// (webvh/scid.ts's note), so a did:webvh identity doesn't exist until it has
// actually been published. This is a network call, not an offline
// derivation — and, per PLANWEBVH.md §2.1, the seed alone cannot recreate
// this DID if the local record is ever lost (SCID persistence lives in the
// anchor, not here).
//
// `domain`/`username` select biset's path-segment identifier
// (PLANWEBVH.md §2.3): did:webvh:{scid}:{domain}:{username} — the fix
// for biset.md/t.biset.md's apex-sharing problem. `relays`/`addresses` seed
// the initial document the same way dht/publish.ts's buildOwnDocument would
// for a did:dht identity.
//
// Not yet wired into account-create.ts — did:dht stays the only path a user
// can actually reach today (PLANWEBVH.md §4 confirms did:webvh as the
// intended default, but wiring it into the account-creation UI is separate,
// larger follow-up work, not part of this function's scope).
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
    ...(old.envelope ? { envelope: old.envelope } : {}),
    ...(old.jmapDevicePublicKey ? { jmapDevicePublicKey: old.jmapDevicePublicKey } : {}),
    ...(old.jmapDevicePrivateKey ? { jmapDevicePrivateKey: old.jmapDevicePrivateKey } : {}),
  }
  await storeDidRecord(record)
  return record
}
