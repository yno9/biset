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
//
// Multi-device (document.ts's DidKeyAgreement note): each device that
// registers with the mediator mints its OWN random DIDComm key and holds its
// own positional slot (kid `#k<n>`) in the published document — not one shared
// key derived from the seed, which would let two devices collide and starve
// each other at the mediator's per-kid delivery queue. `ensureDeviceKey` mints
// this device's key once; `syncDevicePosition` resolves the currently-
// published document (best-effort) to learn its own stable slot and cache
// every sibling device's key. Runs at registration AND on every routine
// republish (publish.ts's buildOwnDocument) — it used to run only once, at
// registration, which meant a device that registered BEFORE a sibling existed
// never learned about it and kept erasing that sibling's key on every one of
// its own later boots (found live: two of one identity's own browsers,
// neither could reach the other, because whichever reopened most recently
// republished a document that had never heard of the other one).
import { deriveRootKey, didFromRootPublicKey, generateDeviceDidCommKey } from './keys.ts'
import { initDid } from './index.ts'
import { getDidRecord, storeDidRecord, withDidLock, type DidRecord } from './store.ts'
import { buildBisetDocument, keyAgreementKeysFromHex, kidN, type DidDocument } from './document.ts'
import { registerDidCommViaDht } from './didcomm/register.ts'
import { resolve, publishDocument, PUBLIC_PKARR_FALLBACKS } from './resolver.ts'
import { didCommGateways } from './publish.ts'
import { hexToBytes } from '../utils.ts'

const MARKER = 'biset_standalone_did'
const bytesToHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

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

/** Mints THIS device's own DIDComm key if it doesn't have one yet. Random, not
 * seed-derived — see the file header. No-op (and no network) if already set. */
async function ensureDeviceKey(rec: DidRecord): Promise<DidRecord> {
  if (rec.didCommPrivateKey && rec.didCommPublicKey) return rec
  const kp = generateDeviceDidCommKey()
  rec.didCommPublicKey = bytesToHex(kp.publicKey)
  rec.didCommPrivateKey = bytesToHex(kp.privateKey)
  await storeDidRecord(rec)
  return rec
}

/** Establishes this device's stable positional slot and refreshes the sibling
 * cache, by resolving whatever document is currently published (best-effort —
 * a resolve failure just means this call learns nothing new, safe to retry
 * later). Establishes `didCommOwnKid` once (kept stable afterward); safe to
 * call again and again to pick up devices registered elsewhere since — and,
 * on a resolve that actually succeeds, to drop a device that's been
 * legitimately REVOKED (unregisterFromMediator) too: the cache is REPLACED
 * with whatever a successful resolve returns, not merged with what was
 * there before, so a revoke actually sticks instead of getting silently
 * restored by the next device that still remembers it. A resolve that
 * fails outright changes nothing (no fresher information to replace the
 * cache with), which is what makes repeating this safe — a transient outage
 * can't be mistaken for "everyone else disappeared". Exported: publish.ts's
 * buildOwnDocument calls this on every routine republish now, not just once
 * at registration — see that file's own note on why skipping it was a real
 * bug, not just an approximation. */
export async function syncDevicePosition(rec: DidRecord, gatewayUrls: string[]): Promise<DidRecord> {
  let resolved: DidDocument | null = null
  try { resolved = await resolve(rec.did, gatewayUrls) } catch { /* best-effort */ }
  const existing = resolved?.keyAgreementKeys ?? []

  if (!rec.didCommOwnKid) {
    // Already published under this exact key (this device registered before,
    // record survived, but didCommOwnKid was never set — e.g. a pre-multi-
    // device record)? Reuse that slot instead of taking a new one.
    const mine = existing.find(k => bytesToHex(k.publicKey) === rec.didCommPublicKey)
    const nextN = existing.length ? Math.max(...existing.map(k => k.n)) + 1 : 1
    rec.didCommOwnKid = mine ? `#k${mine.n}` : `#k${nextN}`
  } else if (resolved) {
    // The slot this device already claims might not actually be OURS on the
    // DHT any more — found live: a device whose local didCommOwnKid/
    // didCommPublicKey had drifted from what's published at that slot (root
    // cause unclear — plausibly a failed resolve at some earlier registration
    // defaulted to #k1 while another device already legitimately held it, per
    // the note below on that exact race). The mediator and every sender only
    // ever trust the PUBLISHED key for a kid, never what a device claims
    // locally — so a mismatch here means this device can never decrypt
    // anything addressed to "its own" kid, silently and permanently, no
    // matter how many times it re-registers under the same wrong slot.
    // Self-heal by disowning the slot and taking a fresh one, exactly like a
    // brand-new device would — only when `resolved` is non-null (a resolve
    // that failed must not be read as "the slot doesn't exist", which would
    // make this fire on every transient network hiccup and reassign kids
    // that were never actually wrong).
    const myN = kidN(rec.didCommOwnKid)
    const published = existing.find(k => k.n === myN)
    if (published && bytesToHex(published.publicKey) !== rec.didCommPublicKey) {
      const nextN = Math.max(...existing.map(k => k.n)) + 1
      rec.didCommOwnKid = `#k${nextN}`
    }
  }
  const myN = kidN(rec.didCommOwnKid)

  // REVERTED to grow-only (never remove an entry, only ever add) — a
  // "replace with whatever a successful resolve returns" version of this
  // was live briefly and caused real, near-unrecoverable damage: a resolve
  // can return HTTP 200 with a validly-signed payload and STILL not reflect
  // every other device — mid-propagation, an incomplete gateway list at that
  // specific call, a race right after a fresh registration hasn't reached
  // every gateway yet — "the request succeeded" is not the same guarantee as
  // "this is the complete, current truth," and trusting it as such let one
  // device's ordinary republish wipe two other real, live devices' keys off
  // the document in one shot. Silently resurrecting a revoked device (the
  // problem this was trying to solve) is a real but recoverable annoyance;
  // silently destroying a live device's key is not. Revocation needs a
  // design that can't fail this way — not resolved here — so it stays a
  // known gap: `unregisterFromMediator` removes a device from the document
  // at the moment it runs, but another device's stale sibling cache can
  // still bring it back on its own next republish, same as before this file
  // ever mentioned replace-on-success.
  // Union of what THIS device has ever removed and what the resolved
  // document's own `rm=` field carries (document.ts's removedKeyNs) — the
  // latter is how a removal performed on a DIFFERENT device of this same
  // identity reaches this one: without it, this device's own local
  // didCommSiblingKeys cache (seeded below) would just keep re-affirming a
  // slot every OTHER device already agreed is gone, since grow-only alone has
  // no way to un-learn something purely from a resolve going quiet on it.
  const removed = new Set([...(rec.didCommRemovedKeys ?? []), ...(resolved?.removedKeyNs ?? []).map(n => `#k${n}`)])
  // Never let THIS device's own kid end up in its own removed set — found
  // live: another device's bulk removal (e.g. from the devices-list trash
  // icon) can legitimately include a kid that's actually still live, and
  // `rm=` propagates that to every device INCLUDING the one it names. Every
  // OTHER device forgives it the moment it sees that kid still present in
  // `existing` (below) — but that forgive check is inside the `k.n === myN`
  // branch's `continue`, which skips itself before ever reaching it, so THIS
  // device could never forgive an entry naming its own kid. Once poisoned it
  // stayed poisoned forever: every future sync re-absorbed it right back from
  // rec.didCommRemovedKeys, and every republish broadcast `rm=` for its own
  // kid to everyone else. Self-removal has its own correct path
  // (unregisterFromMediator clears didCommOwnKid entirely) — this set must
  // never be how it happens.
  removed.delete(`#k${myN}`)
  // Filtered on the way IN too, not just when adding — a removal learned only
  // just now (via `rm=` above) must also evict whatever this device already
  // had cached locally from before it heard about it.
  const siblingMap = new Map(
    (rec.didCommSiblingKeys ?? []).filter(s => !removed.has(s.kid)).map(s => [s.kid, s]),
  )
  for (const k of existing) {
    if (k.n === myN) continue // that's us, not a sibling
    const kid = `#k${k.n}`
    if (removed.has(kid)) {
      // Tombstoned, but it just showed up again in a freshly resolved,
      // validly-signed document — proof it's actually still alive, not the
      // ghost the removal assumed (found live: a device deliberately removed
      // for looking dead kept legitimately republishing itself; the
      // tombstone, once it also started propagating via `rm=`, made every
      // device permanently blind to it regardless). Forgive: a removal only
      // needs to survive long enough that a stale snapshot from right around
      // the delete can't immediately undo it (withDidLock + this `rm=` wave
      // already cover that window) — it was never meant to out-rank the
      // removed device proving itself alive afterward, or "recoverable
      // annoyance" stops being recoverable.
      removed.delete(kid)
    }
    siblingMap.set(kid, { kid, publicKey: bytesToHex(k.publicKey) })
  }
  rec.didCommSiblingKeys = [...siblingMap.values()]
  // Carry the union forward: this device now also knows about anything it
  // just learned from `rm=`, so ITS next publish keeps propagating the full
  // removed set too — the same gossip-by-republish mechanism siblings
  // already use to learn about each other, applied to removals.
  rec.didCommRemovedKeys = [...removed]
  await storeDidRecord(rec)
  return rec
}

/** This device's own entry + every known sibling's, as the array a document
 * publish carries — reads purely from the cached record (see the file header
 * for why buildOwnDocument/this never resolve on a routine publish). */
function fullKeyAgreementKeys(rec: DidRecord) {
  return keyAgreementKeysFromHex(
    rec.didCommPublicKey && rec.didCommOwnKid ? { kid: rec.didCommOwnKid, publicKeyHex: rec.didCommPublicKey } : null,
    (rec.didCommSiblingKeys ?? []).map(s => ({ kid: s.kid, publicKeyHex: s.publicKey })),
  )
}

// Publish the record's document (no relays, mediator service only) to the public
// gateways and (re-)register with the mediator. Idempotent: registerDidCommViaDht
// REPLACES the DIDCommMessaging service rather than appending, so calling it on
// every boot just refreshes the (hours-lived) DHT record and the mediation.
async function publishAndRegister(rec: DidRecord): Promise<void> {
  await ensureDeviceKey(rec)
  const rootPriv = hexToBytes(rec.rootPrivateKey)
  const rootPub = hexToBytes(rec.rootPublicKey)

  const mUrl = rec.didCommMediatorUrl || mediatorUrl()
  if (mUrl) {
    try {
      // Resolve to establish this device's slot + learn siblings only the
      // FIRST time it registers (didCommOwnKid unset) — this runs on every
      // boot (refreshStandalone), so an already-established device publishes
      // from cached local state only, same as buildOwnDocument's normal
      // republish (its note explains why: a transient resolve failure must
      // never look like "no siblings"). A device that goes offline during its
      // very first registration falls back to slot #k1 unconditionally
      // (existing = [] either way) — a possible collision with a sibling it
      // simply couldn't see, self-correcting on the next successful resolve
      // from either device, not silent data loss.
      const gatewayUrls = didCommGateways([], mUrl)
      if (!rec.didCommOwnKid) await syncDevicePosition(rec, gatewayUrls)
      const base: DidDocument = { ...buildBisetDocument(rec.did, rootPub, [], []), keyAgreementKeys: fullKeyAgreementKeys(rec) }
      const reg = await registerDidCommViaDht(hexToBytes(rec.didCommPrivateKey!), kidN(rec.didCommOwnKid!), rootPriv, base, mUrl, gatewayUrls)
      // Persist mediator wiring so a later publishOwnDids rebuilds the document
      // WITH the DIDComm service instead of republishing it away — see store.ts.
      rec.didCommMediatorUrl = reg.mediator.url
      rec.didCommRoutingKey = reg.mediator.doc.keyAgreement?.[0]
      await storeDidRecord(rec)
      return
    } catch (e) {
      console.warn('[standalone] mediator registration skipped (not yet reachable):', e instanceof Error ? e.message : e)
    }
  }

  // No mediator configured, or registration failed: still publish the bare
  // document (identity + this device's key) so the DID exists on the DHT —
  // this publish is the load-bearing step, so it must succeed against at
  // least one public gateway.
  const base: DidDocument = { ...buildBisetDocument(rec.did, rootPub, [], []), keyAgreementKeys: fullKeyAgreementKeys(rec) }
  const published = await publishDocument(rootPriv, base, PUBLIC_PKARR_FALLBACKS)
  if (published === 0) throw new Error('no pkarr gateway accepted the DID document')
}

/** Create a brand-new relay-less identity. Like a normal #new account it takes a
 * password and builds a cryptenv envelope — a relay-less identity is just a
 * normal identity with zero relays — but stores the envelope locally (in its
 * DidRecord) since there is no relay to hold it yet. Returns the master secret so
 * the caller can show the mnemonic (the ultimate backup; the password is the
 * everyday unlock). */
export async function createStandaloneIdentity(password: string): Promise<{ did: string; masterSecret: Uint8Array }> {
  const { buildEnvelope } = await import('../cryptenv.ts')
  const { envelope, masterSecret } = await buildEnvelope(password)
  const did = await registerStandaloneIdentity(masterSecret, envelope)
  return { did, masterSecret }
}

/** Store + publish + mediator-register a relay-less identity from its seed,
 * marking it standalone. Shared by createStandaloneIdentity (fresh, with an
 * envelope) and restore (from the mnemonic, no local envelope — add-relay falls
 * back to the phrase there). Idempotent: initDid returns any existing record. */
export async function registerStandaloneIdentity(masterSecret: Uint8Array, envelope?: import('../cryptenv.ts').Envelope): Promise<string> {
  const root = deriveRootKey(masterSecret)
  const did = didFromRootPublicKey(root.publicKey)
  // Key the DidRecord by the DID itself (no email address exists yet). initDid
  // derives + persists the root/nostr keys from the seed — NOT the DIDComm key,
  // which is this device's own concern (ensureDeviceKey, below).
  const rec = await initDid(did, masterSecret)
  if (!rec) throw new Error('registerStandaloneIdentity: initDid returned null')
  if (envelope) rec.envelope = envelope
  await storeDidRecord(rec)
  await publishAndRegister(rec)
  localStorage.setItem(MARKER, did)
  return did
}

/** Register the CURRENT identity (a logged-in account's, or the relay-less
 * standalone one) with a DIDComm mediator at `mediatorUrl` and persist the
 * result. A mediator needs no account — the DID's own key authenticates — so
 * this is the whole "add a mediator" operation. Shared by the account page's
 * "+ New Relay" mediator branch and the DIDComm debug page. Returns the
 * registration so callers that go on to send/pickup don't need to rebuild it. */
export async function registerWithMediator(rawMediatorUrl: string): Promise<{ own: import('./didcomm/message.ts').DidCommSender; mediator: import('./didcomm/coordinate.ts').MediatorInfo }> {
  // A scheme-less "anchor.biset.md" would otherwise be fetched RELATIVE to the
  // page (file://…/anchor.biset.md, or the app's own origin) — force https.
  const mUrl = /^https?:\/\//i.test(rawMediatorUrl) ? rawMediatorUrl : 'https://' + rawMediatorUrl
  const { sessions } = await import('../context.ts')
  const key = sessions[0]?.account.email ?? standaloneDid()
  if (!key) throw new Error('no identity to register')
  let rec = await getDidRecord(key)
  if (!rec) throw new Error(`no local DID record for ${key}`)
  rec = await ensureDeviceKey(rec)
  // Captured before buildOwnDocument runs — its own internal sync only fires
  // when a slot is ALREADY assigned (see the note below), so this is exactly
  // the signal for whether that already covered this call or not.
  const hadSlotBefore = !!rec.didCommOwnKid

  // Base document: live session state when there are relays, else the record
  // alone (relay-less: no relays, no address).
  const { buildOwnDocument } = await import('./publish.ts')
  const own = await buildOwnDocument(key)
  // own.gateways (relay-backed) is already the full didCommGateways() list —
  // reuse it rather than rebuild. Relay-less: no relay sessions to draw from,
  // but still worth this identity's OWN mediator gateway (mUrl) on top of the
  // public fallbacks, not just the latter — this path used to skip it
  // entirely here (a gap only this consolidation surfaced).
  const gateways = own?.gateways ?? didCommGateways([], mUrl)

  // Everything from here on reads-edits-writes the same DidRecord
  // buildOwnDocument just did — found live: this used to re-run
  // syncDevicePosition unconditionally on the `rec` snapshot captured at the
  // top of this function, entirely outside buildOwnDocument's lock. For an
  // ALREADY-registered device (every boot, via channel.ts's
  // reassertKeylistRegistration → here) buildOwnDocument had ALREADY run
  // syncDevicePosition and persisted its result moments earlier — so this
  // second, unlocked call ran its own separate resolve against a now-stale
  // `rec`, and its own storeDidRecord silently clobbered what buildOwnDocument
  // had just correctly written. On EVERY boot of EVERY already-registered
  // device. Only skip the re-sync when buildOwnDocument is BOTH non-null (a
  // relay-less identity's `own` is always null — its early return happens
  // before it would ever reach its own sync, so THAT case still needs it
  // here) AND this device already had a slot before it ran (buildOwnDocument's
  // own internal sync explicitly skips a slot-less record — nothing to sync
  // yet — so a first-ever registration still needs this explicit call too).
  const reg = await withDidLock(key, async () => {
    let fresh = await getDidRecord(key)
    if (!fresh) throw new Error(`no local DID record for ${key}`)
    fresh = (own && hadSlotBefore) ? fresh : await syncDevicePosition(fresh, gateways)
    const doc: DidDocument = { ...(own?.doc ?? buildBisetDocument(fresh.did, hexToBytes(fresh.rootPublicKey), [], [])), keyAgreementKeys: fullKeyAgreementKeys(fresh) }
    const rootPriv = own?.rootPrivateKey ?? hexToBytes(fresh.rootPrivateKey)
    const result = await registerDidCommViaDht(hexToBytes(fresh.didCommPrivateKey!), kidN(fresh.didCommOwnKid!), rootPriv, doc, mUrl, gateways)
    fresh.didCommMediatorUrl = result.mediator.url
    fresh.didCommRoutingKey = result.mediator.doc.keyAgreement?.[0]
    await storeDidRecord(fresh)
    return result
  })
  return { own: reg.own, mediator: reg.mediator }
}

/** Deregister the current identity's device key from its mediator
 * (keylist-update 'remove') AND revoke this device's key from the published
 * DID document — the mediator card's "Log out". Unlike a relay's "Log out",
 * which only forgets local credentials because the account keeps existing
 * server-side regardless, there is no account here to simply stop using: the
 * keyAgreement entry this device published is the only record of it, and
 * this device is the only one who can ever prove it owns that slot to remove
 * it. Skipping this left every logged-out device's key sitting in the
 * document forever — permanent garbage nobody would ever clean up, since
 * nothing else in the system is in a position to.
 *
 * Two things found live, both fixed here:
 *
 * 1. keylist-update can fail — found live, right after a device's own key
 *    had only just propagated and the mediator's own resolve of it still
 *    404'd — and this used to treat that as fatal, aborting BEFORE the local
 *    cleanup + republish ran at all. The document-side removal matters far
 *    more than the mediator-side one (nobody will ever address a kid that's
 *    not in the document any more, so an orphaned keylist entry is inert;
 *    the reverse — gone from the mediator's keylist but still published — is
 *    what actually breaks things), so keylist-update is now best-effort: log
 *    and continue, always reach the republish below regardless.
 *
 * 2. Used to delete didCommMediatorUrl/didCommRoutingKey along with this
 *    device's own key/kid — but those two fields aren't this device's
 *    private state, they're the IDENTITY's one shared mediator (every device
 *    of one identity registers with the same one — send.ts's own note).
 *    buildOwnDocument decides whether to publish the "didcomm" SERVICE block
 *    at all by checking exactly those two fields on whichever record happens
 *    to run the republish — so clearing them here meant the device doing its
 *    OWN logout would, in the same stroke, drop DIDComm messaging for the
 *    ENTIRE identity out of the document, even with other devices still
 *    live and registered (found live: revoking one device dropped the
 *    "didcomm" service block entirely, breaking every other still-registered
 *    device in one shot). Only this device's own key/kid are cleared now.
 *
 * `identityKey` (a DidRecord's own key — a relay email, or the bare DID for
 * a standalone identity) defaults to the CURRENT session/standalone identity
 * for the mediator card's own "Log out" button, but a caller acting on an
 * identity that's already being logged out elsewhere (left-pane.ts's
 * removeRelayLocally, signing out of an identity's LAST relay) must pass it
 * explicitly — by the time that caller could call this, sessions[] no
 * longer contains the identity being removed, so the implicit lookup would
 * silently resolve to the wrong identity (or none) instead of throwing. */
export async function unregisterFromMediator(identityKey?: string): Promise<void> {
  const { sessions } = await import('../context.ts')
  const key = identityKey ?? sessions[0]?.account.email ?? standaloneDid()
  if (!key) throw new Error('no identity')
  const rec = await getDidRecord(key)
  if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) throw new Error('not registered with a mediator')
  try {
    const { fetchMediatorInfo, updateKeylist } = await import('./didcomm/coordinate.ts')
    const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
    const ownKid = `${rec.did}${rec.didCommOwnKid}`
    const own = { did: rec.did, xKid: ownKid, xPriv: hexToBytes(rec.didCommPrivateKey) }
    await updateKeylist(mediator, own, ownKid, 'remove')
  } catch (e) {
    console.warn('[standalone] mediator keylist-update failed (continuing — the document-side revoke matters more):', e instanceof Error ? e.message : e)
  }

  // Locked: a concurrent routine republish (buildOwnDocument, also lock-
  // protected) might already be mid-flight, holding a rec snapshot read
  // before this logout — waiting for the lock means it finishes (and writes
  // back) first, so this delete then applies on top of it instead of racing
  // to be overwritten by it. See store.ts's withDidLock note.
  await withDidLock(key, async () => {
    const fresh = await getDidRecord(key)
    if (!fresh) return
    delete fresh.didCommOwnKid
    delete fresh.didCommPublicKey
    delete fresh.didCommPrivateKey
    await storeDidRecord(fresh)
  })

  // Republish now, not just leave it to the next routine cycle — the whole
  // point is that this entry must not sit published a moment longer than
  // necessary. keyAgreementKeysFromHex naturally omits this device (own kid
  // is gone above) while keeping every known sibling, so this is a pure
  // removal, nothing else about the document changes. Relay-backed:
  // publishOneVisible rebuilds+republishes the FULL document (relay
  // services included). Relay-less: it's a no-op (buildOwnDocument needs a
  // relay session to build anything at all), so fall back to the same bare
  // republish create-standalone.ts's own no-mediator path already does.
  const { publishOneVisible } = await import('./publish.ts')
  const publishedViaRelay = await publishOneVisible(key).catch(() => false)
  if (!publishedViaRelay) {
    // Re-read post-lock, not the pre-lock `rec` above — that snapshot still
    // has this device's own kid/key set (the lock's delete happened to a
    // separately-fetched copy), so building fullKeyAgreementKeys from it here
    // would republish the very key this call exists to remove.
    const fresh = await getDidRecord(key)
    if (!fresh) return
    const rootPriv = hexToBytes(fresh.rootPrivateKey)
    const rootPub = hexToBytes(fresh.rootPublicKey)
    const base: DidDocument = { ...buildBisetDocument(fresh.did, rootPub, [], []), keyAgreementKeys: fullKeyAgreementKeys(fresh) }
    if (fresh.didCommRemovedKeys?.length) base.removedKeyNs = fresh.didCommRemovedKeys.map(kidN)
    const gatewayUrls = didCommGateways([], fresh.didCommMediatorUrl)
    await publishDocument(rootPriv, base, gatewayUrls).catch(e => console.warn('[standalone] revoke republish failed:', e instanceof Error ? e.message : e))
  }
}

/** Removes ONE device's key from the published DID document — the DIDComm
 * card's per-device trash icon. `kid` matching this identity's own current
 * slot delegates to unregisterFromMediator (self-removal already has a
 * correct path: mediator keylist-update + local key cleanup + republish).
 * A sibling's kid is removed straight out of the local cache and republished
 * immediately, deliberately bypassing buildOwnDocument's normal
 * syncDevicePosition resync (see that function's own note on skipSync) —
 * otherwise the very next resolve-and-remerge inside the SAME publish would
 * re-absorb the entry straight off the still-stale published document,
 * undoing the removal before it ever reaches the network.
 *
 * No revocation proof is asked of the caller: whoever holds this identity's
 * root key can already rewrite the whole document unilaterally (this is a
 * targeted removal of that same authority, not a new one) — see PLAN.md's
 * note on why this stays a human-confirmed action rather than an automatic
 * one keyed off mediator inactivity. */
export async function removeDeviceKey(identityKey: string | undefined, kid: string): Promise<void> {
  const { sessions } = await import('../context.ts')
  const key = identityKey ?? sessions[0]?.account.email ?? standaloneDid()
  if (!key) throw new Error('no identity')

  // Locked (store.ts's withDidLock): read-check-edit-write as one atomic
  // step relative to buildOwnDocument's own lock-protected routine republish
  // — found live, this exact scenario: the routine republish (page boot)
  // reads the record, starts its multi-second network resolve, and THIS
  // delete's read-edit-write completes first; without the shared lock, the
  // routine call's stale (pre-delete) snapshot then finishes and overwrites
  // the deletion when IT saves. Waiting for the lock means it's forced to
  // start (and see) after this delete, not race it.
  const outcome = await withDidLock(key, async () => {
    const rec = await getDidRecord(key)
    if (!rec) throw new Error('no DID record')
    if (kid === rec.didCommOwnKid) return 'self' as const
    const before = rec.didCommSiblingKeys ?? []
    const after = before.filter(s => s.kid !== kid)
    if (after.length === before.length) return 'noop' as const
    rec.didCommSiblingKeys = after
    // Tombstoned BEFORE the publish below, not after: syncDevicePosition
    // checks this set on the very next resolve (including one triggered by
    // this same publish's own callers), so it has to be in place before any
    // resolve can happen, not just before this function returns.
    rec.didCommRemovedKeys = [...new Set([...(rec.didCommRemovedKeys ?? []), kid])]
    await storeDidRecord(rec)
    return 'removed' as const
  })
  if (outcome === 'self') return unregisterFromMediator(key)
  if (outcome === 'noop') return

  // Publish must actually land somewhere, or the removal only ever existed
  // locally — found live: publishDocument doesn't throw on 0 gateways
  // accepting the root (publishOne's own note explains why that's the right
  // default for a routine best-effort republish), but this is a deliberate,
  // user-confirmed action; silently reporting success when nothing reached
  // the network is what let three rapid deletes look like they'd worked while
  // the document never actually changed underneath them.
  const { buildOwnDocument } = await import('./publish.ts')
  const own = await buildOwnDocument(key, { skipSync: true })
  if (own) {
    const accepted = await publishDocument(own.rootPrivateKey, own.doc, own.gateways)
    if (accepted === 0) throw new Error('no gateway accepted the update')
    return
  }
  // Relay-less: buildOwnDocument needs a relay session to build anything at
  // all — same bare-document fallback unregisterFromMediator's own relay-less
  // path uses. Re-read rather than reuse the locked callback's `rec` (out of
  // scope here by design — nothing below this point should see a snapshot
  // older than what was just persisted under the lock).
  const rec = await getDidRecord(key)
  if (!rec) throw new Error('no DID record')
  const rootPriv = hexToBytes(rec.rootPrivateKey)
  const rootPub = hexToBytes(rec.rootPublicKey)
  const base: DidDocument = { ...buildBisetDocument(rec.did, rootPub, [], []), keyAgreementKeys: fullKeyAgreementKeys(rec) }
  if (rec.didCommRemovedKeys?.length) base.removedKeyNs = rec.didCommRemovedKeys.map(kidN)
  const gatewayUrls = didCommGateways([], rec.didCommMediatorUrl)
  const accepted = await publishDocument(rootPriv, base, gatewayUrls)
  if (accepted === 0) throw new Error('no gateway accepted the update')
}

/** True if `url` serves a DIDComm mediator (its /.well-known/did.json is a
 * did:peer) rather than a JMAP relay — so the account page can offer a
 * credential-less "Register" instead of Sign up / Log in. */
export async function isMediatorUrl(url: string): Promise<boolean> {
  try {
    const base = (/^https?:\/\//i.test(url) ? url : 'https://' + url).replace(/\/$/, '')
    const resp = await fetch(base + '/.well-known/did.json')
    if (!resp.ok) return false
    const doc = await resp.json()
    return typeof doc?.id === 'string' && doc.id.startsWith('did:peer:')
  } catch { return false }
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
