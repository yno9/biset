// New-user onboarding (#new page) — username@hostname, mnemonic-only identity
// creation (password/envelope concept disabled, commented out for easy
// revival — see setupNewUserPage's submit handler and index.html's matching
// <!-- --> block).
// import { buildEnvelope } from '../cryptenv.ts'
import { hexToBytes } from '../utils.ts'

const WORDS = [
  'Acid','Amber','Anvil','Arch','Arrow','Ash','Axle','Badge','Bark','Beam',
  'Blade','Blast','Bloom','Bolt','Bond','Bone','Book','Brace','Braid','Branch',
  'Brick','Bridge','Brine','Bronze','Brush','Cage','Cairn','Canal','Cape','Card',
  'Cave','Cedar','Chain','Chalk','Chart','Chase','Chest','Chip','Chord','Clamp',
  'Clay','Cliff','Clip','Cloud','Coal','Coast','Coil','Coin','Comb','Cord',
  'Core','Cork','Cove','Crane','Creek','Crest','Croft','Crown','Crush','Crust',
  'Curl','Curve','Damp','Dart','Dawn','Deck','Dell','Depth','Dome','Draft',
  'Drake','Draw','Drift','Drive','Dune','Dust','Edge','Ember','Epoch','Field',
  'Firth','Flag','Flame','Flash','Flask','Fleet','Flint','Float','Flow','Foam',
  'Fold','Font','Force','Ford','Forge','Fork','Form','Fort','Fray','Frost',
  'Fuel','Gate','Gaze','Gear','Glade','Glare','Glass','Glen','Glide','Glow',
  'Gorge','Grain','Graph','Grasp','Grate','Grave','Grid','Grill','Grip','Grit',
  'Grove','Guard','Guild','Gulf','Haze','Heath','Helm','Hill','Hinge','Hive',
  'Hold','Hook','Horn','Hull','Hunt','Husk','Inch','Isle','Jade','Join',
  'Keel','Kelp','Kiln','Knot','Lake','Lance','Larch','Latch','Leaf','Ledge',
  'Level','Light','Lime','Link','Lobe','Lock','Loft','Loop','Lore','Marsh',
  'Mast','Match','Maze','Mesa','Mesh','Mill','Mine','Mint','Mire','Mist',
  'Moat','Molt','Moor','Moss','Mound','Mount','Mouth','Nave','Node','Notch',
  'Opal','Orb','Orbit','Outcrop','Outlet','Pack','Pane','Patch','Path','Peak',
  'Peat','Pine','Pivot','Plank','Plate','Plume','Pool','Port','Prism','Probe',
  'Quartz','Quest','Rail','Range','Rapid','Reach','Reef','Relay','Resin','Ridge',
  'Ring','Rise','Robe','Rock','Root','Rope','Rune','Rush','Salt','Sand',
  'Shard','Shelf','Shell','Shore','Shoal','Shrine','Silk','Slab','Slate','Sleet',
  'Slope','Smoke','Soak','Soil','Solar','Source','Span','Spark','Spire','Spool',
  'Spray','Sprig','Stack','Staff','Stage','Stalk','Stamp','Steel','Stem','Step',
  'Stone','Storm','Strand','Stream','Strike','Strip','Surge','Sway','Swift','Thorn',
  'Tide','Tile','Timber','Token','Torch','Trace','Track','Trail','Trench','Trunk',
  'Turf','Twist','Vale','Valve','Veil','Vein','Vent','Vine','Void','Wade',
  'Wake','Wall','Ward','Warp','Wave','Weld','Well','Wind','Wing','Wire',
  'Wood','Wound','Wren','Yard','Zone',
]

export function generatePassphrase(): string {
  const arr = new Uint32Array(4)
  crypto.getRandomValues(arr)
  return Array.from(arr).map(n => WORDS[n % WORDS.length]).join('')
}
declare const __BISET_CONFIG__: { hostname?: string } | undefined

// Shared between showNewUserPage (resets/refreshes on every visit) and
// setupNewUserPage (owns the indicator elements) — module-level since the
// two run at different times (page show vs. one-time listener setup). Both
// indicators are purely cosmetic: the submit handler re-checks
// anchorReachable()/smtpReachable() itself rather than trusting whatever was
// last displayed (see setupNewUserPage's applySignupAvailability, which
// drives both the did-method toggle and the email-availability state
// together from the same check — see its own note on why they must not be
// two independent checks).
let resetDidMethodToggle: (() => void) | undefined
let setSignupAvailability: ((mode: 'full' | 'blocked' | 'checking') => void) | undefined
let refreshSignupAvailability: (() => void) | undefined

function getHostname(): string {
  try { return (window as any).__BISET_CONFIG__?.hostname || '' } catch { return '' }
}

// The mail (jmapsmtp) relay this deployment's home identities provision
// against — same explicit-config-or-hostname-convention pattern as
// didcomm-devices.ts's mediatorUrl, so account-create.ts's own submit
// handler (below) and this availability check always agree on the URL.
function getMailUrl(): string {
  const cfg = (window as any).__BISET_CONFIG__
  const hostname = getHostname()
  const url = cfg?.mail_url || (hostname ? `https://mail.${hostname}` : '')
  return url ? url.replace(/\/$/, '') : ''
}

async function smtpReachable(): Promise<boolean> {
  const url = getMailUrl()
  if (!url) return false
  try {
    await fetch(url + '/.well-known/jmap')
    return true
  } catch {
    return false
  }
}

// The AP (ActivityPub, jmapap) relay — optional, unlike mail: this deployment
// may not run one at all (and jmapap itself is slated for removal later), so
// the submit handler treats any failure here as "skip AP", never a signup
// failure — see its own note.
function getApUrl(): string {
  const cfg = (window as any).__BISET_CONFIG__
  const hostname = getHostname()
  const url = cfg?.ap_url || (hostname ? `https://ap.${hostname}` : '')
  return url ? url.replace(/\/$/, '') : ''
}

async function apReachable(): Promise<boolean> {
  const url = getApUrl()
  if (!url) return false
  try {
    await fetch(url + '/.well-known/jmap')
    return true
  } catch {
    return false
  }
}

export function randomHex4(): string {
  const arr = new Uint32Array(1)
  crypto.getRandomValues(arr)
  return (arr[0] & 0xffff).toString(16).padStart(4, '0')
}

export function showNewUserPage() {
  const page = document.getElementById('new-user-page')
  if (!page) return
  page.style.display = 'flex'
  try { history.replaceState(null, '', '#new') } catch {}
  resetDidMethodToggle?.()
  // Whether #new can offer email creation at all — and, tied to the exact
  // same check, which DID method a submit right now would actually use — is
  // a property of this deployment (is its mail relay up? failing that, its
  // anchor?), re-checked every time the page opens, not the user's call, and
  // can change between visits (dev server up/down, flaky network). Starts
  // 'checking' (Start disabled) rather than optimistically 'full', so a fast
  // click can't slip through before the check has actually resolved.
  setSignupAvailability?.('checking')
  refreshSignupAvailability?.()
  const hostnameEl = document.getElementById('nu-hostname')
  if (hostnameEl) hostnameEl.textContent = getHostname()
  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  if (usernameInput) usernameInput.value = randomHex4()
  // password/envelope concept disabled (commented out for easy revival —
  // see index.html's matching <!-- --> block and setupNewUserPage below).
  // const pwInput = document.getElementById('nu-password') as HTMLInputElement
  // if (pwInput) { pwInput.value = generatePassphrase(); pwInput.focus() }
  usernameInput?.focus()
}

function hideNewUserPage() {
  const page = document.getElementById('new-user-page')
  if (page) page.style.display = 'none'
}

export function setupNewUserPage() {
  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  // password/envelope concept disabled (commented out for easy revival —
  // index.html's matching <!-- --> block has the fuller note). These
  // elements no longer exist in the DOM; every reference below is disabled
  // alongside them.
  // const pwInput = document.getElementById('nu-password') as HTMLInputElement
  // const copyBtn = document.getElementById('nu-pw-copy')!
  // const copyIcon = document.getElementById('nu-copy-icon')!
  // const checkIcon = document.getElementById('nu-check-icon')!
  const submitBtn = document.getElementById('nu-submit') as HTMLButtonElement
  const errEl = document.getElementById('nu-error')!
  const tosInput = document.getElementById('nu-tos') as HTMLInputElement
  const tosIcon = document.getElementById('nu-tos-icon')!

  tosInput.addEventListener('change', () => {
    tosIcon.style.opacity = tosInput.checked ? '1' : '0.3'
  })

  // did:dht deprecated (2026-08-11): every identity #new creates is now
  // did:webvh, unconditionally — the method indicator toggle this used to
  // drive (which of two methods a fresh identity would get) no longer has
  // anything to indicate, so it's gone. The dht/webvh buttons in the markup
  // (nu-did-dht-btn/nu-did-webvh-btn), if still present, are simply inert now.
  resetDidMethodToggle = () => {}

  // Whether #new can offer signup at all: needs BOTH the mail relay AND the
  // identity anchor reachable now — username is always required (did:webvh's
  // identifier bakes it in, PLANWEBVH.md §2.3) and did:webvh's genesis needs
  // the anchor up, so unlike before there is no reduced "did-only" mode to
  // fall into when only one of the two answers. 'blocked'/'checking' disable
  // Start; both leave the username row exactly as ordinary 'full' does now
  // (no more hiding/clearing it).
  const usernameRow = document.getElementById('nu-username-row') as HTMLElement | null
  const BLOCKED_MSG = 'No mail relay or identity anchor reachable from here — nothing to connect a new identity to.'
  function applySignupAvailability(mode: 'full' | 'blocked' | 'checking') {
    if (usernameRow) usernameRow.style.display = 'flex'
    submitBtn.style.borderRadius = '0'
    submitBtn.style.alignSelf = 'stretch'
    usernameRow?.appendChild(submitBtn)
    submitBtn.disabled = mode === 'blocked' || mode === 'checking'
    submitBtn.textContent = mode === 'checking' ? 'Checking…' : 'Start'
    if (mode === 'blocked') {
      errEl.textContent = BLOCKED_MSG
      errEl.style.display = 'block'
    } else if (errEl.textContent === BLOCKED_MSG) {
      errEl.textContent = ''
      errEl.style.display = 'none'
    }
  }
  setSignupAvailability = applySignupAvailability
  refreshSignupAvailability = () => {
    Promise.all([
      smtpReachable(),
      import('../did/didcomm-devices.ts').then(({ anchorReachable }) => anchorReachable()),
    ]).then(([smtp, anchor]) => {
      applySignupAvailability(smtp && anchor ? 'full' : 'blocked')
    }).catch(() => {
      applySignupAvailability('blocked')
    })
  }

  // copyBtn.addEventListener('click', async () => {
  //   if (!pwInput.value) return
  //   await navigator.clipboard.writeText(pwInput.value)
  //   copyIcon.style.display = 'none'
  //   checkIcon.style.display = ''
  //   setTimeout(() => { copyIcon.style.display = ''; checkIcon.style.display = 'none' }, 1200)
  // })

  submitBtn.addEventListener('click', async () => {
    const hostname = getHostname()
    const username = usernameInput.value.trim()
    // Username required, always (2026-08-11): did:dht — the one method that
    // could ever produce an identity with no username — is deprecated, and
    // did:webvh always bakes a domain into the identifier
    // (did:webvh:{scid}:{domain}:dids:{username}), so every identity this
    // form creates is username@hostname now. No more separate "kind" of
    // account creation to branch on.
    // password/envelope concept disabled (commented out for easy revival —
    // index.html's matching <!-- --> block has the fuller note): identity
    // creation no longer needs a password at all — the 24-word mnemonic
    // (shown once, at the very end of this handler) is the only recovery
    // material now, and per-device JMAP credentials (vouchThisDevice below,
    // via provisionAccount) don't need one either.
    // const pw = pwInput.value
    // if (!pw) { errEl.textContent = 'Password required'; errEl.style.display = 'block'; return }
    if (!username) { errEl.textContent = 'Username required'; errEl.style.display = 'block'; return }
    if (!hostname) { errEl.textContent = 'hostname not set in config.json'; errEl.style.display = 'block'; return }
    if (!tosInput.checked) { errEl.textContent = 'Please agree to the Terms of Beta-testing'; errEl.style.display = 'block'; return }

    submitBtn.disabled = true
    submitBtn.textContent = 'Generating…'
    errEl.style.display = 'none'

    try {
      // const { envelope, kek, masterSecret } = await buildEnvelope(pw)
      const masterSecret = crypto.getRandomValues(new Uint8Array(32))
      const { deriveKek } = await import('../cryptenv.ts')
      const kek = await deriveKek(masterSecret)
      const envelope: import('../cryptenv.ts').Envelope | undefined = undefined
      submitBtn.textContent = 'Creating…'

      // Root DID identity: always derived first, regardless of whether a
      // relay is being added right now (did is the essential key concept —
      // store.ts's file header). The envelope is kept in the DidRecord
      // itself from here on, not only on a relay — the one thing every
      // identity now has locally, so unsealing it later never depends on a
      // relay being reachable (unsealCurrentIdentity, provision.ts).
      //
      // did:webvh (PLANWEBVH.md §4) needs a username to build its
      // path-segment identifier and is unavailable whenever email creation
      // isn't (no username — see applySignupAvailability's note), so it
      // only ever applies when hasUsername is true. Computed fresh here
      // rather than trusting whatever the page-open indicator last showed —
      // that was cosmetic and may be stale (anchor state can change, or the
      // async check may not have resolved yet if the user submits fast);
      // this is the one check that actually decides. Not short-circuited
      // away when hasUsername is false — mediator registration below needs
      // this same result regardless of whether there's a username at all
      // (DID⊥relay orthogonality: DIDComm reachability and email are
      // independent axes).
      // did:dht deprecated (2026-08-11): it used to be the fallback whenever
      // did:webvh couldn't apply (no username, or the anchor unreachable).
      // Username is required now (above), and did:webvh's genesis needs the
      // anchor to be up — so an anchor outage now fails signup outright
      // rather than silently falling back to a different method. Re-checked
      // fresh here (not trusted from the page-open indicator, which may be
      // stale) since this is the one check that actually decides.
      const { initDidWebvh } = await import('../did/index.ts')
      const { storeDidRecord } = await import('../did/store.ts')
      const { setOwnDid, anchorReachable } = await import('../did/didcomm-devices.ts')
      const anchorOk = await anchorReachable()
      if (!anchorOk) {
        errEl.textContent = 'Identity anchor unreachable — cannot create an account right now.'
        errEl.style.display = 'block'
        submitBtn.textContent = 'Create'; submitBtn.disabled = false
        return
      }
      const didRecord = await initDidWebvh(masterSecret, { domain: hostname, username, relays: [], addresses: [] })
      didRecord.envelope = envelope
      await storeDidRecord(didRecord)
      setOwnDid(didRecord.did)
      const rootPriv = hexToBytes(didRecord.rootPrivateKey)

      const email = `${username}@${hostname}`
      // A home identity may span two relays: mail (jmapsmtp) and
      // ActivityPub (jmapap), both provisioned with the same envelope so
      // the identity anchor ties them to one owner — but neither is
      // actually required (see mailOk/apOk below): an identity is a real,
      // usable thing on its own, relays are optional add-ons it may or
      // may not end up with right now (store.ts's file header).
      const mailUrl = getMailUrl()
      const apUrl = getApUrl()

      // Provision the home mail relay: signature-based DID binding + THIS
      // device's own per-device credential, established atomically with
      // the account itself (this session's account-model redesign,
      // src/did/devicebind.ts's file header) — no masterSecret-derived
      // static token anywhere any more.
      //
      // `username` is baked directly into the DID string itself
      // (did:webvh:{scid}:{domain}:dids:{username} — PLANWEBVH.md §2.3), so
      // a non-conflict mail failure here is fatal too, same as a conflict —
      // falling back would publish a resolvable document that CLAIMS this
      // address without ever having actually bound it (the "two different
      // people, same-looking name" confusion a mismatched webvh
      // username/email would cause). No silent fallback.
      const { provisionAccount } = await import('../did/provision.ts')
      const relayFail = (label: string, r: { conflict?: boolean; status: number }) => {
        errEl.textContent = r.conflict ? 'Username taken' : `${label} server error (${r.status})`
        errEl.style.display = 'block'
        submitBtn.textContent = 'Create'; submitBtn.disabled = false
      }
      const mailRes = await provisionAccount({ serverUrl: mailUrl, username, did: didRecord.did, rootPrivateKey: rootPriv, envelope })
      if (!mailRes.ok) {
        // The did:webvh genesis is already live on the anchor by this point
        // (see the note above) — stamp it deactivated so it doesn't sit
        // there looking like a valid, resolvable claim on an address it
        // never actually got. Best-effort: this failure is already fatal
        // to the signup either way, so a deactivate failure just leaves
        // the known-issue window open a little longer, not a new one.
        const { deactivateDocument } = await import('../did/webvh/publish.ts')
        await deactivateDocument(didRecord.did, rootPriv, hexToBytes(didRecord.rootPublicKey))
          .catch(e => console.warn('[account-create] deactivateDocument failed (non-fatal):', e instanceof Error ? e.message : e))
        relayFail('mail', mailRes)
        return
      }
      const mailOk = mailRes.ok

      // AP (ActivityPub) is optional — jmapap may not be deployed at all
      // for this host, or simply unreachable right now (and is slated for
      // removal entirely later). Unlike mail, any failure here just means
      // this identity goes mail-only, never a failed signup: the account
      // holder can always add it later (custom-domain.ts's "+ New Relay").
      let apOk = false
      try {
        if (await apReachable()) {
          const apRes = await provisionAccount({ serverUrl: apUrl, username, did: didRecord.did, rootPrivateKey: rootPriv, envelope })
          apOk = apRes.ok
        }
      } catch (e) {
        console.warn('[account-create] AP provisioning failed (non-fatal, AP is optional):', e instanceof Error ? e.message : e)
      }

      // did:webvh has no background relay-sync yet (PLANWEBVH.md §6
      // remaining work), so the freshly-created identity's document would
      // otherwise list no relays at all until one gets added manually.
      // Best-effort: a failure here still leaves a valid, resolvable (if
      // relay-less-looking) identity — never worth failing account creation
      // over.
      {
        const { updateDocument } = await import('../did/webvh/publish.ts')
        const relays: Array<{ id: string; serverUrl: string; protocol: string; address: string }> = []
        if (mailOk) relays.push({ id: 'mail', serverUrl: mailUrl, protocol: 'mail', address: email })
        if (apOk) relays.push({ id: 'ap', serverUrl: apUrl, protocol: 'activitypub', address: email })
        await updateDocument({
          did: didRecord.did, rootPrivateKey: rootPriv, rootPublicKey: hexToBytes(didRecord.rootPublicKey),
          relays, addresses: email,
        }).catch(e => console.warn('[account-create] webvh relay sync failed (non-fatal):', e instanceof Error ? e.message : e))
      }

      submitBtn.textContent = 'Connecting…'
      // No password to store — provisionAccount established THIS device's
      // own per-device credential directly (device.ts's file header),
      // there is nothing the relay hands back any more. jmap/client.ts's
      // initSession always tries the device-signed session login first
      // whenever account.did is set, so the empty string here is never
      // actually presented as a credential — it's a placeholder, not a
      // fallback (there's nothing legacy for it to fall back to for an
      // account created this way).
      //
      // Only attempt to connect whichever relay actually got provisioned
      // (mailOk/apOk) — connectAndPersist's initPGPForSession no-ops on
      // the AP relay (no PGP key store there) regardless. Zero attempts
      // (both mail and AP failed non-conflict — a rare double-race) is
      // not itself an error: it just means this identity ends up
      // relay-less, same as if smtpReachable had said so up front. At
      // least one attempt that all still fail to connect IS worth
      // surfacing — a freshly-provisioned account failing to log in
      // points at something actually broken.
      const { connectAndPersist } = await import('../app.ts')
      const attempts = []
      if (mailOk) attempts.push(connectAndPersist({ serverUrl: mailUrl, email, password: '', did: didRecord.did }, kek))
      if (apOk) attempts.push(connectAndPersist({ serverUrl: apUrl, email, password: '', did: didRecord.did }, kek))
      if (attempts.length) {
        const sessions = await Promise.all(attempts)
        if (!sessions.some(s => s)) {
          errEl.textContent = 'Login failed after creation'; errEl.style.display = 'block'
          submitBtn.textContent = 'Create'; submitBtn.disabled = false
          return
        }
      }

      hideNewUserPage()
      const { showApp, showSysMsg, startPolling } = await import('./shell.ts')
      showApp()
      const { setupLeftPane, showMenuPage, loadLeftInboxes } = await import('./left-pane.ts')
      await setupLeftPane()

      // Mediator registration (2026-07-26 policy reversal — used to be
      // deliberately opt-in, see [[project_biset_did_relay_orthogonality]]
      // and ARC.md's "Account & relay flows"; now follows the same "if
      // reachable, use it" pattern this whole signup flow uses for mail/AP).
      // anchorOk is always true here — signup returned early above otherwise.
      //
      // Fire-and-forget, NOT awaited before navigating below — unlike mail/AP
      // (one HTTP round trip each), registerWithMediator is a multi-step
      // DIDComm protocol dance (publish keys, mediate-request, keylist-update,
      // republish), each its own network call with no explicit timeout.
      // Awaiting it here (as a first cut did) meant a slow or unresponsive
      // mediator left the whole signup stuck on #new with the app shell
      // showing empty behind it — found live. refreshAccountsList() is called
      // again once it lands so the mediator card (left-pane.ts's
      // buildMediatorCard, which only checks the DidRecord once at render
      // time) appears without the user needing to manually reload; harmless
      // no-op if they've already navigated away from /account by then.
      ;(async () => {
        const { registerWithMediator, mediatorUrl } = await import('../did/didcomm-devices.ts')
        const reg = await registerWithMediator(mediatorUrl())
        const { setupDidCommChannel } = await import('../did/didcomm/channel.ts')
        await setupDidCommChannel(reg.own.did, () => { import('./shell.ts').then(s => s.fetchMessages()); loadLeftInboxes() })
        const { refreshAccountsList } = await import('./left-pane.ts')
        refreshAccountsList()
      })().catch(e => console.warn('[account-create] mediator registration failed (non-fatal):', e instanceof Error ? e.message : e))

      const { refreshAccountsList, openComposeTo } = await import('./left-pane.ts')
      startPolling()
      refreshAccountsList()
      // Pending-DM handoff: a visitor who arrived via /<user> (or #compose/<addr>)
      // had the chat target stashed by showUserLanding — open compose to it rather
      // than dropping on the account page.
      const { takePendingDm } = await import('./user-landing.ts')
      const pending = takePendingDm()
      if (pending) openComposeTo(pending)
      else showMenuPage('/account')
      showSysMsg('Account created')

      // Show the recovery phrase once, now — this is the only safety valve for
      // the rotation-less root identity (DID.md). masterSecret is in hand here;
      // it isn't persisted, so this first showing is the natural moment.
      const { showMnemonic } = await import('./mnemonic.ts')
      showMnemonic(masterSecret, didRecord.did, { firstTime: true })

      // Publishing is no longer opt-in-only: the mediator registration above
      // already published as part of its own 3-phase publish cycle.
    } catch (e) {
      errEl.textContent = 'Error: ' + (e instanceof Error ? e.message : String(e))
      errEl.style.display = 'block'
      submitBtn.textContent = 'Create'; submitBtn.disabled = false
    }
  })

  // "Restore with recovery phrase" is a link to the standalone #restore page
  // (setupRestorePage/showRestorePage below), not an inline toggle — a
  // did:webvh restore needs a second field (the DID) that doesn't belong
  // cluttering the ordinary signup form. main.ts calls setupRestorePage()
  // alongside this on every route that can reach either page, so its
  // listeners exist by the time this link (or #restore's own "Back" link)
  // is clicked.
  const restoreToggle = document.getElementById('nu-restore-toggle')
  restoreToggle?.addEventListener('click', () => showRestorePage())
}

// ── Recovery-phrase login (#restore page) ───────────────────────────────────
// 24 words → seed → DID → resolve relays → connect. No password, no need to
// know your relays/address (the DID document supplies them) for did:dht. The
// optional DID field is did:webvh-only (see did/restore.ts's file header for
// why that method needs it and did:dht doesn't) — left blank, it's simply
// unused.
export function showRestorePage() {
  const page = document.getElementById('restore-page')
  if (!page) return
  hideNewUserPage()
  page.style.display = 'flex'
  try { history.replaceState(null, '', '#restore') } catch {}
  document.getElementById('rp-phrase')?.focus()
}

function hideRestorePage() {
  const page = document.getElementById('restore-page')
  if (page) page.style.display = 'none'
}

export function setupRestorePage() {
  const backLink = document.getElementById('rp-back')
  const phraseEl = document.getElementById('rp-phrase') as HTMLTextAreaElement | null
  const didEl = document.getElementById('rp-did') as HTMLInputElement | null
  const submitBtn = document.getElementById('rp-submit') as HTMLButtonElement | null
  const errEl = document.getElementById('rp-error')

  backLink?.addEventListener('click', () => {
    hideRestorePage()
    showNewUserPage()
  })

  submitBtn?.addEventListener('click', async () => {
    if (!phraseEl || !errEl) return
    const phrase = phraseEl.value.trim()
    if (!phrase) { errEl.textContent = 'Enter your recovery phrase'; errEl.style.display = 'block'; return }
    const did = didEl?.value.trim() || undefined
    errEl.style.display = 'none'
    submitBtn.disabled = true; submitBtn.textContent = 'Restoring…'
    try {
      const { restoreFromMnemonic } = await import('../did/restore.ts')
      const res = await restoreFromMnemonic(phrase, did)
      if ('error' in res) { errEl.textContent = res.error; errEl.style.display = 'block'; return }
      // restoreFromMnemonic already persisted + registered + PGP'd each
      // session via connectAndPersist — nothing left to do here but reflect
      // the outcome in the UI.
      const hasRelays = res.sessions.length > 0
      hideRestorePage()
      const { showApp, showSysMsg, startPolling } = await import('./shell.ts')
      showApp()
      const { setupLeftPane, showMenuPage, refreshAccountsList } = await import('./left-pane.ts')
      await setupLeftPane()
      if (hasRelays) startPolling()
      // Unconditional, not just when hasRelays — restore.ts's own mediator
      // registration (fire-and-forget, may still be in flight) refreshes
      // this again once it lands, but a relay-less identity still needs
      // this FIRST call so /account isn't left showing stale/empty state
      // right after restoring (this used to run only inside `if
      // (hasRelays)`, which is exactly backwards for a relay-less identity —
      // that's the one case with nothing else to trigger a render at all).
      refreshAccountsList()
      showMenuPage('/account')
      showSysMsg(hasRelays ? 'Identity restored' : 'Identity restored (no relay)')
    } catch (e) {
      errEl.textContent = 'Restore failed: ' + (e instanceof Error ? e.message : String(e))
      errEl.style.display = 'block'
    } finally {
      submitBtn.disabled = false; submitBtn.textContent = 'Restore'
    }
  })
}
