// Relay-less identity (DID⊥relay orthogonality, project memory): create a DID
// that has NO relay account at all — reachable only through the DIDComm mediator
// — and add relays later as an optional step. This is the symmetric counterpart
// to anchorless relays (a relay with no DID); here, a DID with no relay.
//
// Everything a normal account needs a relay for is skipped:
//   - no envelope (that is password-recovery state a relay stores; recovery here
//     is the mnemonic alone)
//   - no provisionAccount (that binds the DID to a relay-hosted address)
//   - no relay gateways to publish through — the DID document goes to the PUBLIC
//     pkarr fallbacks, and reachability comes from the mediator, not a relay.
//
// The identity lives ONLY as a DidRecord (keyed by the DID itself, since there
// is no email address yet) plus a localStorage marker so boot can find it with
// zero StoredAccounts present.
import { deriveRootKey, didFromRootPublicKey } from './keys.ts'
import { initDid } from './index.ts'
import { getDidRecord, storeDidRecord, type DidRecord } from './store.ts'
import { buildBisetDocument } from './document.ts'
import { registerDidCommViaDht } from './didcomm/register.ts'
import { publishDocument, PUBLIC_PKARR_FALLBACKS } from './resolver.ts'
import { hexToBytes } from '../utils.ts'

const MARKER = 'biset_standalone_did'

/** Which DIDComm mediator this deployment registers standalone identities with.
 * Not in relay config (a standalone identity has no relay), so it is derived
 * from the app host — anchor.<apex> — or taken from an explicit config key. */
export function mediatorUrl(): string {
  const cfg = (window as any).__BISET_CONFIG__ || {}
  if (cfg.mediator_url) return cfg.mediator_url
  const host: string = cfg.hostname || ''
  const apex = host.split('.').slice(-2).join('.') // t.biset.md -> biset.md
  return apex ? `https://anchor.${apex}` : ''
}

/** The DID of the standalone identity this browser holds, if any. */
export function standaloneDid(): string | null {
  return localStorage.getItem(MARKER)
}

export function clearStandalone(): void {
  localStorage.removeItem(MARKER)
}

// Publish the record's document (no relays, mediator service only) to the public
// gateways and (re-)register with the mediator. Idempotent: registerDidCommViaDht
// REPLACES the DIDCommMessaging service rather than appending, so calling it on
// every boot just refreshes the (hours-lived) DHT record and the mediation.
async function publishAndRegister(rec: DidRecord): Promise<void> {
  const rootPriv = hexToBytes(rec.rootPrivateKey)
  const rootPub = hexToBytes(rec.rootPublicKey)
  // The document this identity resolves to: no relays, no mailto address, but
  // carrying _k1 so it is a complete DIDComm-capable document. This publish is
  // the load-bearing step — it is what makes the DID exist on the DHT — so it
  // must succeed against at least one public gateway.
  const base = buildBisetDocument(rec.did, rootPub, [], [])
  const withK1 = { ...base, keyAgreementKey: hexToBytes(rec.didCommPublicKey!) }
  const published = await publishDocument(rootPriv, withK1, PUBLIC_PKARR_FALLBACKS)
  if (published === 0) throw new Error('no pkarr gateway accepted the DID document')

  // Mediator registration = relay-less REACHABILITY. Best-effort and separate:
  // the current biset-anchor mediator cannot yet resolve a did:dht sender's key
  // (it decodes did:peer only), so this registration fails against it today —
  // that is the Phase C work (teach the mediator a did:dht resolver). The
  // identity is fully created either way; it just isn't mediator-reachable until
  // then (relays added later via identity-home make it reachable the normal way).
  const mUrl = rec.didCommMediatorUrl || mediatorUrl()
  if (mUrl) {
    try {
      const reg = await registerDidCommViaDht(hexToBytes(rec.didCommPrivateKey!), rootPriv, base, mUrl, PUBLIC_PKARR_FALLBACKS)
      // Persist mediator wiring so a later publishOwnDids rebuilds the document
      // WITH the DIDComm service instead of republishing it away — see store.ts.
      rec.didCommMediatorUrl = reg.mediator.url
      rec.didCommRoutingKey = reg.mediator.doc.keyAgreement?.[0]
      await storeDidRecord(rec)
    } catch (e) {
      console.warn('[standalone] mediator registration skipped (not yet reachable):', e instanceof Error ? e.message : e)
    }
  }
}

/** Create a brand-new relay-less identity from a fresh master seed. The caller
 * owns seed generation + showing the mnemonic (seedToMnemonic) for backup —
 * the mnemonic is the ONLY recovery path (no relay, no envelope). */
export async function createStandaloneIdentity(masterSeed: Uint8Array): Promise<{ did: string }> {
  const root = deriveRootKey(masterSeed)
  const did = didFromRootPublicKey(root.publicKey)
  // Key the DidRecord by the DID itself (no email address exists yet). initDid
  // derives + persists all sub-keys (root/nostr/_k1) from the seed.
  const rec = await initDid(did, masterSeed)
  if (!rec) throw new Error('createStandaloneIdentity: initDid returned null')
  await publishAndRegister(rec)
  localStorage.setItem(MARKER, did)
  return { did }
}

/** Boot-time refresh: if this browser holds a standalone identity, republish its
 * document + renew mediation, and return its DID. No seed needed — every key is
 * already in the DidRecord. Best-effort: a failed republish must not block boot
 * (the identity still exists locally; it just may be briefly unresolvable). */
export async function refreshStandalone(): Promise<string | null> {
  const did = standaloneDid()
  if (!did) return null
  const rec = await getDidRecord(did)
  if (!rec) { clearStandalone(); return null }
  try { await publishAndRegister(rec) } catch (e) { console.warn('[standalone] republish failed:', e) }
  return did
}
