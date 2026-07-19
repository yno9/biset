export * from './seed.ts'
export * from './keys.ts'
export * from './store.ts'
export * from './resolver.ts'
export { buildBisetDocument, documentToRecords, recordsToDocument } from './document.ts'
export { buildSignedPayload, parseSignedPayload, nowSeq } from './packet.ts'
export { seenSeq, noteSeq } from './freshness.ts'

import { deriveRootKey, deriveNostrKey, didFromRootPublicKey } from './keys.ts'
import { getDidRecord, storeDidRecord, type DidRecord } from './store.ts'

const toHex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

// Ensures this email has a locally-derived DID identity, deriving it from the
// master seed on first call (creation, or first login after rollout for
// existing accounts — DID.md's "lazy migration") and reusing the stored
// record on every subsequent call (reload, or an existing account that
// already migrated) without needing the seed again — same pattern as PGP's
// initPGP()/getKeyRecord() early-return.
//
// Does NOT touch the DIDComm (_k1) key — that's a per-DEVICE concern now, not
// a per-IDENTITY one (document.ts's DidKeyAgreement note), so it's minted
// lazily by create-standalone.ts the first time THIS device registers with a
// mediator, never derived here from the seed.
export async function initDid(email: string, masterSeed?: Uint8Array): Promise<DidRecord | null> {
  const existing = await getDidRecord(email)
  if (existing) return existing
  if (!masterSeed) return null

  const root = deriveRootKey(masterSeed)
  const nostr = deriveNostrKey(masterSeed)
  const record: DidRecord = {
    email,
    did: didFromRootPublicKey(root.publicKey),
    rootPublicKey: toHex(root.publicKey),
    rootPrivateKey: toHex(root.privateKey),
    nostrPublicKey: toHex(nostr.publicKey),
    nostrPrivateKey: toHex(nostr.privateKey),
  }
  await storeDidRecord(record)
  return record
}
