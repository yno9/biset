// New-user onboarding (#new page) — username@hostname, mnemonic-only identity
// creation (password/envelope concept disabled, commented out for easy
// revival — see setupNewUserPage's submit handler and index.html's matching
// <!-- --> block).
// import { buildEnvelope } from '../cryptenv.ts'
import { hexToBytes } from '../utils.ts'
import { apOutboundUrl } from '../ap/config.ts'
import { mailRelayUrl } from '../context.ts'

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

// Shared between refreshNewUserPage (resets/refreshes on every visit) and
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
// The DID published by whatever address is currently typed into #new, or
// null when that name is free (2026-08-12). Set by the debounced DNS-anchor
// lookup in setupNewUserPage; read by the submit handler to decide whether
// this is a signup or a login, and by applySignupAvailability to label the
// button. Module-level for the same reason the two above are: the lookup and
// the handlers that consume it are wired at different times.
let loginDidForTypedName: string | null = null

/** The #new submit button's resting label: this form is a signup until the
 * typed address turns out to already exist, at which point it's a login. */
function signupButtonLabel(): string {
  return loginDidForTypedName ? 'Log in' : 'Start'
}

// Set when the user clicks the `@hostname` suffix on #new and types a
// different one (2026-08-17, user-requested) — this build's own
// __BISET_CONFIG__.hostname is baked in at deploy time (one deployment,
// one domain), which is right for signup but leaves no way to log into an
// identity on a DIFFERENT biset domain from a page built for this one (e.g.
// this build serves t.biset.md, the identity to restore is `y@biset.md`).
// Session-only: reset on reload, exactly like the random default username
// refreshNewUserPage rolls every visit.
let hostnameOverride: string | null = null

// Exported: left-pane.ts's unclaimed mail-relay card (renderAccountsList)
// needs the identical hostname/URL this file's own submit handler uses, so
// the two never compute a different "home mail relay" for the same identity.
export function getHostname(): string {
  if (hostnameOverride) return hostnameOverride
  try { return (window as any).__BISET_CONFIG__?.hostname || '' } catch { return '' }
}

// The mail (jmapsmtp) relay this deployment's home identities provision
// against — same explicit-config-or-hostname-convention pattern as
// didcomm-devices.ts's mediatorUrl, so account-create.ts's own submit
// handler (below) and this availability check always agree on the URL.
export function getMailUrl(): string {
  const cfg = (window as any).__BISET_CONFIG__
  const hostname = getHostname()
  const url = cfg?.mail_url || (hostname ? mailRelayUrl(hostname) : '')
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

// The AP (ActivityPub) relay — retired (2026-08-16, see ap/config.ts's
// AP_ENABLED), so this now always resolves to '' and apReachable() below
// always short-circuits false; the submit handler already treats that as
// "skip AP", never a signup failure, so nothing else here needed to change.
function getApUrl(): string {
  const url = apOutboundUrl((window as any).__BISET_CONFIG__)
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

// Everything opening #new does EXCEPT deciding where it's shown — shared by
// the full-page overlay (showNewUserPage) and the inline mount on the
// account page (mountNewUserPageInline).
function refreshNewUserPage(opts: { focus: boolean }) {
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
  // A fresh random name — free by definition, and set programmatically so no
  // `input` event fires to clear the previous visit's lookup for us.
  loginDidForTypedName = null
  if (usernameInput) usernameInput.value = randomHex4()
  // password/envelope concept disabled (commented out for easy revival —
  // see index.html's matching <!-- --> block and setupNewUserPage below).
  // const pwInput = document.getElementById('nu-password') as HTMLInputElement
  // if (pwInput) { pwInput.value = generatePassphrase(); pwInput.focus() }
  if (opts.focus) usernameInput?.focus()
}

// ── Inline mount on the account page (2026-08-12, user-requested; the only
// way #new is shown at all since 2026-08-16 — the separate full-page
// overlay is gone, #account now owns account creation/restore entirely) ──
// With zero accounts, #account shows this signup form in place of a bare
// "No accounts" line — the one thing there is to do from that page anyway.
//
// The ELEMENT is moved rather than cloned or re-templated: setupNewUserPage
// binds its listeners by id (getElementById), so a clone would either
// duplicate every id in the document or arrive with no handlers at all.
// Moving the live node keeps every listener attached exactly once.

export function mountNewUserPageInline(container: HTMLElement, opts: { centered?: boolean } = {}): void {
  const page = document.getElementById('new-user-page')
  if (!page) return
  if (page.parentElement !== container) container.appendChild(page)
  // In-flow, not a fixed full-bleed overlay: no inset/z-index/background of
  // its own. Centred vertically only when this is the only thing on the page
  // (`centered`, the historical zero-account case) — with nothing else there,
  // top-aligning it leaves the form clinging to the header above a screen of
  // blank space, so min-height gives `justify-content` an axis to centre
  // within (a flex column only centres inside height it actually has), and
  // it's a floor rather than a fixed height so a small window just grows and
  // scrolls instead of clipping the form. With account cards already below it
  // (a DID-less relay account exists but no DID identity yet — 2026-08-19,
  // user-reported: the create-identity option must stay reachable even then)
  // that same min-height would shove those real, already-connected accounts
  // off-screen for no reason, so it sits at its natural size instead.
  const centered = opts.centered ?? true
  page.setAttribute('style', centered
    ? 'display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:calc(100vh - 220px);padding:4px 0 20px'
    : 'display:flex;flex-direction:column;align-items:center;padding:4px 0 20px')
  // The "biset / beta" masthead belongs to a full-page takeover; inside the
  // account page it's a second app title under the one already on screen.
  const title = page.querySelector<HTMLElement>('.biset-title')
  if (title) title.style.display = 'none'
  // No focus grab — this form shares the page with the account list and the
  // "+ New Relay" button, so stealing the caret on every render would fight
  // whatever the user was actually doing.
  refreshNewUserPage({ focus: false })
}

/** Parks the node back in `document.body`, hidden. Called before anything
 * replaces the account page's markup — otherwise the node would be
 * destroyed along with the container it's parked in, and #account would be
 * permanently missing its signup form for the rest of the session. */
export function unmountNewUserPageInline(): void {
  const page = document.getElementById('new-user-page')
  if (!page) return
  page.style.display = 'none'
  const title = page.querySelector<HTMLElement>('.biset-title')
  if (title) title.style.display = ''
  if (page.parentElement !== document.body) document.body.appendChild(page)
}

function hideNewUserPage() {
  const page = document.getElementById('new-user-page')
  if (page) page.style.display = 'none'
}

// Both setup functions bind listeners with addEventListener and are called
// from several routes (main.ts's #new and #restore branches both call BOTH,
// and route() re-runs on every hashchange) — so without a guard the same
// handler stacks up and a single submit fires it N times. Latent before the
// account page started mounting this form inline too; not latent any more.
let _newUserPageWired = false
let _restorePageWired = false

export function setupNewUserPage() {
  if (_newUserPageWired) return
  _newUserPageWired = true
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

  // ── Editable @hostname (2026-08-17) ──────────────────────────────────────
  // Click the suffix to type a different biset domain than this build's own
  // __BISET_CONFIG__.hostname — see hostnameOverride's own note on why this
  // exists at all. Swapped for a plain <input> on click rather than made
  // permanently editable, so the common case (this deployment's own domain,
  // no override needed) still reads as inert label text.
  const hostnameEl = document.getElementById('nu-hostname')
  if (hostnameEl) {
    hostnameEl.style.cursor = 'pointer'
    hostnameEl.title = 'Click to log into an identity on a different biset domain'
    hostnameEl.addEventListener('click', () => {
      if (hostnameEl.querySelector('input')) return // already editing
      const current = getHostname()
      hostnameEl.textContent = ''
      const input = document.createElement('input')
      input.type = 'text'
      input.value = current
      input.autocomplete = 'off'
      input.spellcheck = false
      input.style.cssText = 'width:9em;border:none;background:transparent;color:inherit;font:inherit;outline:none;padding:0;text-align:right'
      hostnameEl.appendChild(input)
      input.focus()
      input.select()

      // `cancelled` guards against blur's own commit firing a second time
      // after Escape already reverted — blur() still dispatches even on a
      // detached input, so without this Escape's revert would be
      // immediately overwritten by commit() reading the untouched value.
      let cancelled = false
      const commit = () => {
        if (cancelled) return
        const typed = input.value.trim().toLowerCase()
        hostnameOverride = typed || null
        hostnameEl.textContent = getHostname()
        // Same input the username field's own listener re-runs the DNS
        // lookup on — dispatched rather than duplicating that logic here, so
        // changing domain re-checks "is this a login?" against the NEW
        // domain immediately, exactly as if the name had just been retyped.
        usernameInput.dispatchEvent(new Event('input'))
      }
      input.addEventListener('blur', commit)
      input.addEventListener('keydown', ev => {
        if (ev.key === 'Enter') { ev.preventDefault(); input.blur() }
        if (ev.key === 'Escape') { ev.preventDefault(); cancelled = true; hostnameEl.textContent = current; input.blur() }
      })
    })
  }

  // ── "is this name already someone's?" (2026-08-12) ──────────────────────
  // Typing an address that already exists turns this form into a login
  // rather than a signup — restore stopped being a separate concept the
  // moment the DID could be discovered from the address itself. The check is
  // the address's DNS anchor (`_did.<user>.<domain>` TXT, discovery.ts's own
  // DoH client), NOT the webvh log: the log is the thing a login actually
  // needs, but it is ~1MB for an established identity, which is absurd to
  // fetch on every keystroke. The TXT record is a few hundred bytes and
  // carries the full DID, which is exactly what the login then needs to
  // resolve that log — so the cheap check hands the expensive step its input.
  let lookupSeq = 0
  let lookupTimer: ReturnType<typeof setTimeout> | null = null
  const phraseEl = document.getElementById('nu-phrase') as HTMLTextAreaElement | null
  const signPhraseEl = document.getElementById('nu-sign-phrase') as HTMLTextAreaElement | null
  // Set only after the Root Key has been checked against this exact DID and
  // its document says a distinct current Sign Key controls updates. Changing
  // either the address or Root Key clears it, so a Sign Key pasted for one
  // identity can never be submitted for another.
  let signKeyRequiredForDid: string | null = null
  // Grows with the phrase instead of offering a drag handle: a recovery
  // phrase is pasted, not composed, so the only useful height is "however
  // tall the thing you just pasted is". Four rows is the resting size — one
  // line short of it looks like a single-line field and invites typing a
  // password into it.
  const PHRASE_MIN_ROWS = 4
  const autosizePhrase = (el: HTMLTextAreaElement | null) => {
    if (!el) return
    const cs = getComputedStyle(el)
    // `lineHeight: normal` computes to the string, not a px value — fall back
    // to the usual ~1.4×font-size rather than producing NaN.
    const line = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.4
    const padding = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom)
    // box-sizing is border-box here, so the height we set includes borders —
    // but scrollHeight doesn't, hence adding them back on.
    const borders = parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth)
    el.style.height = 'auto' // let scrollHeight shrink back down, not just grow
    const content = Math.max(el.scrollHeight, line * PHRASE_MIN_ROWS + padding)
    el.style.height = `${content + borders}px`
  }
  phraseEl?.addEventListener('input', () => {
    autosizePhrase(phraseEl)
    signKeyRequiredForDid = null
    if (signPhraseEl) { signPhraseEl.value = ''; signPhraseEl.style.display = 'none' }
  })
  signPhraseEl?.addEventListener('input', () => autosizePhrase(signPhraseEl))
  const applyTypedNameLookup = (did: string | null) => {
    loginDidForTypedName = did
    signKeyRequiredForDid = null
    // Never override 'Checking…'/disabled — availability owns that state and
    // re-renders the label itself when it resolves.
    if (!submitBtn.disabled) submitBtn.textContent = signupButtonLabel()
    // The phrase box only exists for the login case: an existing address
    // can't be signed up for, and a free one has no phrase to check against.
    // Cleared on the way out so a half-typed phrase can't survive into a
    // different address's login.
    if (phraseEl) {
      phraseEl.style.display = did ? '' : 'none'
      if (!did) phraseEl.value = ''
      // Only measurable once it's actually displayed (a hidden element has
      // no scrollHeight), so size it here rather than at wiring time.
      if (did) autosizePhrase(phraseEl)
    }
    if (signPhraseEl) {
      signPhraseEl.style.display = 'none'
      signPhraseEl.value = ''
    }
  }
  usernameInput.addEventListener('input', () => {
    // Optimistically back to signup the instant the name changes: a stale
    // "Log in" on a name that no longer resolves is the one wrong answer
    // that would actually mislead (it sends the user off looking for a
    // recovery phrase for an account that doesn't exist).
    applyTypedNameLookup(null)
    if (lookupTimer) clearTimeout(lookupTimer)
    const typed = usernameInput.value.trim()
    const hostname = getHostname()
    if (!typed || !hostname) return
    const seq = ++lookupSeq
    lookupTimer = setTimeout(async () => {
      let did: string | null = null
      try {
        const { lookupDidForAddressFresh } = await import('../did/discovery.ts')
        did = await lookupDidForAddressFresh(`${typed}@${hostname}`)
      } catch { /* offline / DoH refused — treat as "free", the signup path */ }
      // Two staleness guards, not one: `seq` catches a later lookup already
      // in flight, and the value comparison catches the field having moved
      // on to something this answer was never about (including
      // refreshNewUserPage's programmatic reset, which fires no input event).
      if (seq !== lookupSeq || usernameInput.value.trim() !== typed) return
      applyTypedNameLookup(did)
    }, 400)
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
    submitBtn.textContent = mode === 'checking' ? 'Checking…' : signupButtonLabel()
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
    // (did:webvh:{scid}:{domain}:{username}), so every identity this
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
    // This address already exists: log in instead of trying to create it
    // (which would 409 at the relay anyway). Checked BEFORE the terms
    // checkbox — an existing account agreed to them when it was created,
    // and re-gating an ordinary login behind them is nonsense.
    if (loginDidForTypedName) {
      await logInExistingAddress(`${username}@${hostname}`, loginDidForTypedName, phraseEl, signPhraseEl, {
        get signKeyRequired() { return signKeyRequiredForDid === loginDidForTypedName },
        requireSignKey() { signKeyRequiredForDid = loginDidForTypedName },
        clearSignKeyRequirement() { signKeyRequiredForDid = null },
      }, errEl, submitBtn)
      return
    }
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
      const { createIdentity } = await import('../did/create.ts')
      const { storeDidRecord } = await import('../did/store.ts')
      let didRecord: import('../did/store.ts').DidRecord
      try {
        ;({ didRecord } = await createIdentity(masterSecret, username, hostname))
      } catch (e) {
        errEl.textContent = e instanceof Error ? e.message : String(e)
        errEl.style.display = 'block'
        submitBtn.textContent = 'Create'; submitBtn.disabled = false
        return
      }
      didRecord.envelope = envelope
      await storeDidRecord(didRecord)
      // Read the root key BEFORE enabling at-rest protection: enabling it
      // re-writes every record with the seed and root key sealed, and the rest
      // of this handler signs with them. The session stays unlocked either
      // way, so this is about holding the value rather than re-reading a
      // record that no longer carries it in the clear.
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

      // Mail is no longer provisioned here at all (2026-08-16, "claim
      // account" redesign — [account.ts]'s per-relay card, unclaimed by
      // default): signup now only ever creates the DID. The home mail
      // relay card on #account starts unclaimed and provisions on demand
      // when the user explicitly clicks "Claim account" — same
      // `provisionAccount` call this used to make eagerly here, just moved
      // to `claimMailAccount` in left-pane.ts so a slow or unreachable mail
      // relay at signup time no longer blocks identity creation at all
      // (previously fatal: a mail failure used to deactivate the DID that
      // was just created, on the theory that a resolvable-but-unbound
      // document was worse than no identity — that trade-off doesn't apply
      // once mail is opt-in rather than assumed).
      const { provisionAccount } = await import('../did/provision.ts')
      const mailOk = false

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
        const identityPub = hexToBytes(didRecord.rootPublicKey)
        await updateDocument({
          did: didRecord.did, signingPrivateKey: rootPriv, signingPublicKey: identityPub, identityPublicKey: identityPub,
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
        const { registerIdentityChannel } = await import('../did/create.ts')
        await registerIdentityChannel(didRecord.did, () => { import('./shell.ts').then(s => s.fetchMessages()); loadLeftInboxes() })
        const { refreshAccountsList } = await import('./left-pane.ts')
        refreshAccountsList()
      })().catch(e => console.warn('[account-create] mediator registration failed (non-fatal):', e instanceof Error ? e.message : e))

      const { refreshAccountsList } = await import('./left-pane.ts')
      startPolling()
      refreshAccountsList()
      showMenuPage('/account')
      showSysMsg('Account created')

      // Show the recovery phrase, and offer passkey protection as the user
      // dismisses it.
      //
      // **The enrolment has to hang off a real click.** WebAuthn's
      // `credentials.create()` requires transient activation — a few seconds
      // from an actual user gesture — and this handler spends far longer than
      // that on the network before reaching here (anchorReachable, the
      // genesis PUT, provisioning). Called inline it was rejected every time
      // and swallowed, so accounts came out unprotected with no trace
      // (2026-08-14, user-reported). `onClose` fires from the dialog's own
      // "I've saved it" click, which is both a fresh gesture and the moment
      // the user has just been told this phrase is the only copy.
      const { showMnemonic } = await import('./mnemonic.ts')
      showMnemonic(masterSecret, {
        firstTime: true,
        onClose: () => {
          import('../did/store.ts')
            .then(async m => {
              const ok = await m.enableIdentityProtection(`${username}@${hostname}`)
              if (!ok) console.warn('[identity] passkey protection not enabled — secrets stay plaintext at rest')
            })
            .catch(e => console.warn('[identity] passkey protection failed:', e instanceof Error ? e.message : e))
        },
      })

      // Publishing is no longer opt-in-only: the mediator registration above
      // already published as part of its own 3-phase publish cycle.
    } catch (e) {
      errEl.textContent = 'Error: ' + (e instanceof Error ? e.message : String(e))
      errEl.style.display = 'block'
      submitBtn.textContent = 'Create'; submitBtn.disabled = false
    }
  })

}

// ── Recovery-phrase login ───────────────────────────────────────────────────
// 24 words → seed → resolve the DID's document → connect its relays. There is
// no separate "restore" page any more (2026-08-12, user-requested): restoring
// an identity and logging into one were always the same operation, and the
// only reason they were split was that a did:webvh restore needed a DID
// string the user had to know. It doesn't — the address's own DNS anchor
// publishes it (setupNewUserPage's lookup), so the address the user was
// already typing is enough, and the phrase box appears under it in place.
async function logInExistingAddress(
  address: string,
  did: string,
  phraseEl: HTMLTextAreaElement | null,
  signPhraseEl: HTMLTextAreaElement | null,
  signKeyStep: { readonly signKeyRequired: boolean; requireSignKey(): void; clearSignKeyRequirement(): void },
  errEl: HTMLElement,
  submitBtn: HTMLButtonElement,
): Promise<void> {
  const phrase = phraseEl?.value.trim() ?? ''
  if (!phrase) {
    errEl.textContent = `${address} already exists — paste its 24-word Root Key phrase to log in`
    errEl.style.display = 'block'
    phraseEl?.focus()
    return
  }
  errEl.style.display = 'none'
  submitBtn.disabled = true
  submitBtn.textContent = 'Logging in…'
  try {
    // Root Key is always step one. Inspect the document before persisting
    // anything so a DID whose current update key has rotated away from its
    // Root Key gets a clear, inline Sign Key step rather than a successful
    // login followed by the account page's late "FIX" prompt.
    if (!signKeyStep.signKeyRequired) {
      const { restoreKeyRequirements } = await import('../did/restore.ts')
      const requirements = await restoreKeyRequirements(phrase, did)
      if ('error' in requirements) { errEl.textContent = requirements.error; errEl.style.display = 'block'; return }
      if (requirements.needsSignKey) {
        signKeyStep.requireSignKey()
        if (signPhraseEl) {
          signPhraseEl.style.display = ''
          signPhraseEl.focus()
        }
        errEl.textContent = 'Key rotation is active — now paste this identity\'s current 24-word Sign Key phrase.'
        errEl.style.display = 'block'
        return
      }
    }

    const signPhrase = signPhraseEl?.value.trim() ?? ''
    if (signKeyStep.signKeyRequired && !signPhrase) {
      errEl.textContent = 'Paste the 24-word Sign Key phrase to continue.'
      errEl.style.display = 'block'
      signPhraseEl?.focus()
      return
    }
    const { restoreFromMnemonic } = await import('../did/restore.ts')
    const res = await restoreFromMnemonic(phrase, did, signKeyStep.signKeyRequired ? signPhrase : undefined)
    if ('error' in res) { errEl.textContent = res.error; errEl.style.display = 'block'; return }
    // restoreFromMnemonic already persisted + registered + PGP'd each session
    // via connectAndPersist — nothing left to do here but reflect the outcome.
    const hasRelays = res.sessions.length > 0
    hideNewUserPage()
    unmountNewUserPageInline()
    const { showApp, showSysMsg, startPolling } = await import('./shell.ts')
    showApp()
    const { setupLeftPane, showMenuPage, refreshAccountsList } = await import('./left-pane.ts')
    await setupLeftPane()
    if (hasRelays) startPolling()
    // Unconditional, not just when hasRelays — restore.ts's own mediator
    // registration (fire-and-forget, may still be in flight) refreshes this
    // again once it lands, but a relay-less identity still needs this FIRST
    // call so /account isn't left showing stale/empty state right after
    // logging in: that's the one case with nothing else to trigger a render.
    refreshAccountsList()
    showMenuPage('/account')
    showSysMsg(hasRelays ? 'Logged in' : 'Logged in (no relay)')
    signKeyStep.clearSignKeyRequirement()
  } catch (e) {
    errEl.textContent = 'Log in failed: ' + (e instanceof Error ? e.message : String(e))
    errEl.style.display = 'block'
  } finally {
    submitBtn.disabled = false
    submitBtn.textContent = signKeyStep.signKeyRequired ? 'Continue' : signupButtonLabel()
  }
}
