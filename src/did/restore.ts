// Recovery-phrase login: 24 words → full identity restore, with no password and
// no need to remember which relays or address (DID.md's "restore on any device"
// — the payoff of rotation-less + seed derivation). The seed yields the root
// key and the PGP KEK directly; resolving the DID yields the relay list +
// address; the root key then VOUCHES this device at each relay (this
// session's account-model redesign, src/did/devicebind.ts) so the restored
// identity can actually log into JMAP, not just be recovered locally — there
// is no masterSecret-derived static token any more for jmap/client.ts's
// initSession to fall back to.
//
// did:webvh breaks the "seed alone" part: its SCID depends on genesis TIME,
// not just the root key (webvh/publish.ts's createGenesis), so the DID string
// itself cannot be rederived offline the way did:dht's can. A did:webvh
// restore therefore needs the DID string as a second input (the UI's
// optional "DID" field) — this still isn't a password or any relay-derived
// secret, so DID⊥relay holds: what's being checked is "does this seed
// control this DID", via the document's own published root key, not
// anything a relay issued.
import { mnemonicToSeed, isValidMnemonic } from './seed.ts'
import { deriveRootKey } from './keys.ts'
import { resolveAny } from './resolver.ts'
import { fetchCurrentLog } from './webvh/log-io.ts'
import { encodeMultikey } from './webvh/multikey.ts'
import type { DidDocument } from './document.ts'
import { rootPublicKeyFromWebvhState, type WebvhDidDocument } from './webvh/document.ts'
import { bisetWebvhUsername, parseWebvhDid } from './webvh/identifier.ts'
import { mediatorUrl, setOwnDid } from './didcomm-devices.ts'
import { deriveKek } from '../cryptenv.ts'
import { bytesToHex, firstServiceEndpoint } from '../utils.ts'
import type { StoredAccount, AccountSession } from '../types.ts'
import { ed25519 } from '@noble/curves/ed25519.js'

export interface RestoreResult {
  did: string
  primaryAddress: string
  // Empty when the identity's published document lists no relays (only a
  // mediator, or nothing at all) — the caller shows the normal account page
  // either way, an identity with zero relays being the ordinary case now
  // (store.ts's file header), not a distinct "standalone" outcome to branch
  // on separately.
  sessions: AccountSession[]
  kek: Uint8Array
}

/** What the login UI needs to know after the Root Key step. The Sign Key is
 * required only after pre-rotation has actually moved `updateKeys` away from
 * the identity's Root Key. Merely enabling the rotation feature still leaves
 * the Root Key as the current signer, so asking for a second phrase there
 * would be needless friction. */
export interface RestoreKeyRequirements {
  needsSignKey: boolean
  /** The public multikey the Sign Key phrase must produce, for a live UI
   * fingerprint/check. Absent when the Root Key is still the signer. */
  signKeyFingerprint?: string
}

function akaMail(addrs: string[]): string | null {
  for (const a of addrs) if (a.startsWith('mailto:')) return a.slice('mailto:'.length)
  return null
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function normalizePhrase(phrase: string): string {
  return phrase.trim().toLowerCase().replace(/\s+/g, ' ')
}

export function restoreNeedsSignKey(updateKeys: string[] | undefined, rootPublicKey: Uint8Array): boolean {
  return !!updateKeys?.length && !updateKeys.includes(encodeMultikey(rootPublicKey))
}

/** Checks the Root Key and inspects the current signing authority without
 * writing a local record. This deliberately backs the first, Root-Key-only
 * screen of restore: the caller can insert a Sign Key step before any login
 * or background DIDComm work begins. */
export async function restoreKeyRequirements(mnemonic: string, did?: string): Promise<RestoreKeyRequirements | { error: string }> {
  const phrase = normalizePhrase(mnemonic)
  if (!isValidMnemonic(phrase)) return { error: 'Invalid Root Key phrase (check the 24 words and their order).' }

  const suppliedDid = did?.trim()
  if (!suppliedDid || !suppliedDid.startsWith('did:webvh:')) {
    return { error: 'DID required (did:webvh:…) — check it was typed correctly.' }
  }
  const resolved = await resolveAny(suppliedDid)
  if (!resolved) return { error: 'Could not resolve that DID — check it was typed correctly, or its relays may be offline.' }

  const root = deriveRootKey(mnemonicToSeed(phrase))
  const rootKey = rootPublicKeyFromWebvhState(resolved as WebvhDidDocument)
  if (!rootKey || !bytesEqual(rootKey, root.publicKey)) {
    return { error: 'This Root Key phrase does not control that DID.' }
  }

  try {
    const { last } = await fetchCurrentLog(suppliedDid)
    const updateKeys = last.parameters.updateKeys
    if (!restoreNeedsSignKey(updateKeys, root.publicKey)) return { needsSignKey: false }
    return { needsSignKey: true, signKeyFingerprint: updateKeys?.[0] }
  } catch (e) {
    return { error: `Could not check this DID's current Sign Key: ${e instanceof Error ? e.message : String(e)}` }
  }
}

// Returns a human-readable error string on failure, or the restored identity.
// `did` is required now (2026-08-11: did:dht deprecated — that was the only
// method whose DID could be rederived from the seed alone with no field to
// fill in; did:webvh always needs one, see file header).
export async function restoreFromMnemonic(mnemonic: string, did?: string, signKeyMnemonic?: string): Promise<RestoreResult | { error: string }> {
  const phrase = normalizePhrase(mnemonic)
  if (!isValidMnemonic(phrase)) return { error: 'Invalid Root Key phrase (check the 24 words and their order).' }

  const masterSecret = mnemonicToSeed(phrase)
  const root = deriveRootKey(masterSecret)
  const suppliedDid = did?.trim()
  if (!suppliedDid || !suppliedDid.startsWith('did:webvh:')) {
    return { error: 'DID required (did:webvh:…) — check it was typed correctly.' }
  }

  const resolved = await resolveAny(suppliedDid)
  if (!resolved) return { error: 'Could not resolve that DID — check it was typed correctly, or its relays may be offline.' }
  const rootKey = rootPublicKeyFromWebvhState(resolved as WebvhDidDocument)
  if (!rootKey || !bytesEqual(rootKey, root.publicKey)) {
    return { error: 'This Root Key phrase does not control that DID.' }
  }
  const resolvedDid: string = suppliedDid
  const doc: DidDocument | WebvhDidDocument = resolved

  // The Root Key proves who the identity is and vouches the device to a
  // relay, but after a pre-rotation has been spent it no longer has authority
  // to publish this DID document. Validate and retain the current Sign Key
  // during restore instead of letting the first mediator registration fail
  // later and make the account page ask for it as a surprise "FIX".
  let signingKey: { privateKey: Uint8Array; publicKey: Uint8Array } | null = null
  try {
    const { last } = await fetchCurrentLog(resolvedDid)
    const updateKeys = last.parameters.updateKeys
    if (restoreNeedsSignKey(updateKeys, root.publicKey)) {
      const signPhrase = normalizePhrase(signKeyMnemonic ?? '')
      if (!isValidMnemonic(signPhrase)) {
        return { error: 'This DID uses key rotation. Enter its current 24-word Sign Key phrase too.' }
      }
      const privateKey = mnemonicToSeed(signPhrase)
      const publicKey = ed25519.getPublicKey(privateKey)
      if (!updateKeys?.includes(encodeMultikey(publicKey))) {
        return { error: "This Sign Key phrase does not control the DID's current document." }
      }
      signingKey = { privateKey, publicKey }
    }
  } catch (e) {
    return { error: `Could not check this DID's current Sign Key: ${e instanceof Error ? e.message : String(e)}` }
  }

  // Persist the DID record (keyed by did — store.ts's file header) so
  // grouping/publish work after restore without re-deriving. No DIDComm key
  // here — that's a per-DEVICE concern now (document.ts's DidKeyAgreement
  // note), minted lazily by this device the first time it registers with a
  // mediator. Runs regardless of whether the document lists any relay — an
  // identity's local record and its relay count are unrelated (no more
  // "restore as standalone" special case).
  const { localDidRecord } = await import('./index.ts')
  const local = await localDidRecord(masterSecret, resolvedDid)
  if (signingKey) {
    const { storeDidRecord } = await import('./store.ts')
    await storeDidRecord({
      ...local,
      signingPrivateKey: bytesToHex(signingKey.privateKey),
      signingPublicKey: bytesToHex(signingKey.publicKey),
    })
  }
  setOwnDid(resolvedDid)
  // Passkey protection is NOT attempted here, even though this is the moment
  // the device receives the seed: `credentials.create()` needs transient
  // activation, and by this point the login click is many network round
  // trips old (resolve, vouch, connect) — the call would just be rejected.
  // The identity menu's "Protect with passkey" (left-pane.ts) offers it from
  // a real click instead.

  // Re-register THIS device with the identity's mediator, if the resolved
  // document shows one — user-caught gap (2026-07-27): restore never had
  // this, unlike #new's signup (that day's earlier "mediator auto-
  // registration" fix). DIDComm keys are strictly per-device, so whichever
  // device registered before this restore is irrelevant to THIS one — and
  // the assumption that reassertKeylistRegistration (channel.ts) would
  // catch this at the next boot doesn't hold either: it only fires on a
  // full page load (restore never reloads, it just continues the same
  // session), and even then only for a device whose LOCAL DidRecord
  // already has didCommMediatorUrl set — which a just-restored device
  // never does, having no registration history of its own. Uses the
  // mediator THIS IDENTITY's own document names (its DIDCommMessaging
  // service endpoint), not this deployment's config default, so restoring
  // on a different biset deployment than the one originally used still
  // finds the right one. Fire-and-forget, same reasoning as the #new fix:
  // registerWithMediator is a multi-step network dance with no timeout and
  // must never block restore itself.
  // If the document names no mediator at all, this identity may simply have
  // been CREATED while this deployment's anchor was unreachable (did:dht's
  // mail/AP provisioning doesn't depend on the anchor, unlike did:webvh which
  // requires it up-front — so an anchor outage at signup silently produces a
  // did:dht identity with no DIDCommMessaging service anywhere, ever, and no
  // later boot self-heals it: reassertKeylistRegistration in channel.ts only
  // replays a LOCAL didCommMediatorUrl that also never got set). Fall back to
  // the same live probe #new's signup uses (anchorReachable()) and, if the
  // anchor is up now, register with this deployment's default mediator —
  // mirroring account-create.ts's policy instead of only replaying history.
  const mediatorSvc = doc.service.find(s => s.type === 'DIDCommMessaging')
  let mediatorEndpoint = mediatorSvc ? firstServiceEndpoint(mediatorSvc.serviceEndpoint) : ''
  if (!mediatorEndpoint) {
    const { anchorReachable, mediatorUrl: defaultMediatorUrl } = await import('./didcomm-devices.ts')
    if (await anchorReachable()) mediatorEndpoint = defaultMediatorUrl()
  }
  if (mediatorEndpoint) {
    (async () => {
      const { registerWithMediator } = await import('./didcomm-devices.ts')
      const reg = await registerWithMediator(mediatorEndpoint)
      const { setupDidCommChannel } = await import('./didcomm/channel.ts')
      await setupDidCommChannel(reg.own.did, () => {
        import('../ui/shell.ts').then(s => s.fetchMessages())
        import('../ui/left-pane.ts').then(m => m.loadLeftInboxes())
      })
      // The account page may already have rendered once by the time this
      // (fire-and-forget, network-bound) registration actually lands — same
      // "refresh once it lands" fix as #new's own mediator registration, so
      // the mediator card (left-pane.ts's buildMediatorCard, which only
      // checks the DidRecord once at render time) appears without a manual
      // reload.
      const { refreshAccountsList } = await import('../ui/left-pane.ts')
      refreshAccountsList()
    })().catch(e => console.warn('[restore] mediator registration failed (non-fatal):', e instanceof Error ? e.message : e))
  }

  // A relay service carries an address (the account's mailbox/actor at that
  // relay); the DIDCommMessaging service (the mediator) does not. No relay
  // services at all: nothing left to connect, same as any other identity
  // with zero relays.
  const relayServices = doc.service.filter(s => !!s.address)
  if (relayServices.length === 0) {
    return { did: resolvedDid, primaryAddress: '', sessions: [], kek: new Uint8Array(0) }
  }

  const kek = await deriveKek(masterSecret)
  const primaryAddress = akaMail(doc.alsoKnownAs) ?? doc.service[0].address ?? ''

  // Connect every relay the DID lists, each at its own address (service.address).
  // Vouch THIS device first — best-effort per relay, same as an unreachable
  // relay always was: a relay this device can't vouch at (or can't reach)
  // is simply skipped, not a hard failure for the whole restore. The vouch
  // targets whatever key currently controls the DID (rootKeyResolver
  // follows did:webvh rotation, and did:dht's key IS the identifier), so
  // this works unchanged regardless of any later root-key rotation.
  const { connectAndPersist } = await import('../app.ts')
  const { vouchThisDevice, deviceLabel, scidLoginAddress } = await import('./provision.ts')
  const label = deviceLabel()
  const sessions: AccountSession[] = []
  // biset's own convention (server.rs's own note, jmapsmtp ARC.md §2.9): a
  // did:webvh identifier's trailing path segment always names the SAME
  // localpart the mail address at that domain uses — so it is a BETTER
  // source for the human-facing display address than `svc.address` /
  // `alsoKnownAs`, which live in routing.json and can drift out of sync
  // with reality (found live 2026-08-18: this exact DID's routing.json had
  // been overwritten with its own SCID-login address in both fields, by
  // the self-reinforcing loop `refreshDisplayEmail`/`liveRelayInputs` could
  // form before this fix — see those functions' own notes). Preferred
  // whenever the DID actually has a path-shaped username; falls back to
  // whatever the document says for a DID that doesn't (an apex DID, or a
  // foreign did:webvh convention with no username segment biset can read).
  let webvhHome: string | undefined
  try {
    const username = bisetWebvhUsername(resolvedDid)
    if (username) webvhHome = `${username}@${parseWebvhDid(resolvedDid).domain}`
  } catch { /* not a path-shaped did:webvh — nothing to prefer */ }

  for (const svc of relayServices) {
    const serverUrl = firstServiceEndpoint(svc.serviceEndpoint).replace(/\/$/, '')
    if (!serverUrl) continue
    const displayEmail = webvhHome || svc.address || primaryAddress
    if (!displayEmail) continue
    // The DID document's own service.address is a delivery ALIAS
    // (PLANSCID.md) — never necessarily the address this device logs in
    // as. scidLoginAddress resolves the real login identity straight from
    // the DID string; displayEmail (below) stays the human-facing one for
    // everything the user actually sees.
    const login = await scidLoginAddress(resolvedDid, displayEmail)
    if (!login) continue
    const { email, username, domain } = login
    // vouchThisDevice resolves {ok:false} rather than throwing on a rejected
    // vouch (a genuine HTTP error, not a transport failure) — a bare .catch
    // here only ever caught the transport-failure case, so a REJECTED vouch
    // (bad signature, relay-side policy, whatever) was completely invisible:
    // the subsequent connectAndPersist just failed too, with no trace of why
    // (user-caught 2026-07-27, "Found the identity but could not connect to
    // any of its relays" with zero further detail).
    const vouch = await vouchThisDevice({ serverUrl, username, domain, did: resolvedDid, rootPrivateKey: root.privateKey, label })
      .catch(e => { console.warn(`[restore] vouchThisDevice(${serverUrl}) threw:`, e instanceof Error ? e.message : e); return { ok: false, status: 0 } })
    if (!vouch.ok) console.warn(`[restore] vouchThisDevice(${serverUrl}) rejected: HTTP ${vouch.status}`)
    const stored: StoredAccount = { serverUrl, email, displayEmail, password: '', did: resolvedDid }
    // A vouch and the first session login reach different relay paths.  The
    // vouch may already have returned 200 while the login path still sees its
    // previous device snapshot; a browser reload seconds later then succeeds
    // with no user action.  One 800ms retry did not cover that window in
    // production.  Bound the recovery here instead: successful vouches get
    // five login attempts over ten seconds, while a rejected vouch remains a
    // real failure and is not retried pointlessly.
    let session: AccountSession | null = null
    const attempts = vouch.ok ? 5 : 1
    for (let attempt = 0; attempt < attempts && !session; attempt++) {
      if (attempt > 0) await new Promise(r => setTimeout(r, attempt * 1000))
      session = await connectAndPersist(stored, kek)
    }
    if (session) { session.account.did = resolvedDid; sessions.push(session) }
    else console.warn(`[restore] connectAndPersist(${serverUrl}) returned no session (vouch ${vouch.ok ? 'ok' : `HTTP ${vouch.status}`})`)
  }
  if (!sessions.length) return { error: 'Found the identity but could not connect to any of its relays.' }

  // Restore is also an identity selection. Without this, a successful restore
  // leaves `biset_active_identity` empty until a later reload happens to
  // adopt the newly persisted account, which makes the post-restore state
  // needlessly ambiguous to both the UI and diagnostics.
  const { setActiveIdentity } = await import('../context.ts')
  setActiveIdentity(resolvedDid)

  return { did: resolvedDid, primaryAddress: primaryAddress || sessions[0].account.displayEmail || sessions[0].account.email, sessions, kek }
}
