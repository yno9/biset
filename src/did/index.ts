export * from './seed.ts'
export * from './keys.ts'
export * from './store.ts'
export * from './resolver.ts'
export { buildBisetDocument, documentToRecords, recordsToDocument } from './document.ts'
export { buildSignedPayload, parseSignedPayload, nowSeq } from './packet.ts'
export { seenSeq, noteSeq } from './freshness.ts'

import { deriveRootKey, deriveNostrKey, deriveDidCommKey, didFromRootPublicKey } from './keys.ts'
import { getDidRecord, storeDidRecord, type DidRecord } from './store.ts'

const toHex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

// Ensures this email has a locally-derived DID identity, deriving it from the
// master seed on first call (creation, or first login after rollout for
// existing accounts — DID.md's "lazy migration") and reusing the stored
// record on every subsequent call (reload, or an existing account that
// already migrated) without needing the seed again — same pattern as PGP's
// initPGP()/getKeyRecord() early-return.
export async function initDid(email: string, masterSeed?: Uint8Array): Promise<DidRecord | null> {
  const existing = await getDidRecord(email)
  if (existing) {
    // Lazy migration: _k1 (DIDComm, PLAN.md "DIDComm transport identity")
    // was added to DidRecord after some accounts already had one — a
    // password entry (masterSeed available) is exactly the moment to
    // backfill it, same pattern as this whole function already is.
    if (!existing.didCommPrivateKey && masterSeed) {
      const didComm = deriveDidCommKey(masterSeed)
      existing.didCommPublicKey = toHex(didComm.publicKey)
      existing.didCommPrivateKey = toHex(didComm.privateKey)
      await storeDidRecord(existing)
    }
    return existing
  }
  if (!masterSeed) return null

  const root = deriveRootKey(masterSeed)
  const nostr = deriveNostrKey(masterSeed)
  const didComm = deriveDidCommKey(masterSeed)
  const record: DidRecord = {
    email,
    did: didFromRootPublicKey(root.publicKey),
    rootPublicKey: toHex(root.publicKey),
    rootPrivateKey: toHex(root.privateKey),
    nostrPublicKey: toHex(nostr.publicKey),
    nostrPrivateKey: toHex(nostr.privateKey),
    didCommPublicKey: toHex(didComm.publicKey),
    didCommPrivateKey: toHex(didComm.privateKey),
  }
  await storeDidRecord(record)
  return record
}
