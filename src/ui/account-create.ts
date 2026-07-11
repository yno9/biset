// Account creation overlay — username@hostname + password
import { buildEnvelope, authTokenToBasicAuth } from '../cryptenv.ts'

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
import { initSession } from '../jmap/client.ts'
import { addSession } from '../context.ts'
import { loadStoredAccounts, saveStoredAccounts } from '../context.ts'
import { initPGPForSession } from '../app.ts'
import { refreshAccountsList } from './left-pane.ts'
import { showSysMsg } from './shell.ts'

declare const __BISET_CONFIG__: { hostname?: string } | undefined

function getHostname(): string {
  try { return (window as any).__BISET_CONFIG__?.hostname || '' } catch { return '' }
}

export function setupAccountCreateOverlay() {
  const overlay = document.getElementById('acc-create-overlay')
  if (!overlay) return

  const hostnameEl = document.getElementById('acc-create-hostname')!
  const usernameInput = document.getElementById('acc-create-username') as HTMLInputElement
  const pwInput = document.getElementById('acc-create-password') as HTMLInputElement
  const submitBtn = document.getElementById('acc-create-submit') as HTMLButtonElement
  const errEl = document.getElementById('acc-create-error')!

  hostnameEl.textContent = getHostname()

  const copyBtn = document.getElementById('acc-create-pw-copy')!
  const copyIcon = document.getElementById('acc-pw-copy-icon')!
  const checkIcon = document.getElementById('acc-pw-check-icon')!
  copyBtn.addEventListener('click', async () => {
    if (!pwInput.value) return
    await navigator.clipboard.writeText(pwInput.value)
    copyIcon.style.display = 'none'
    checkIcon.style.display = ''
    setTimeout(() => { copyIcon.style.display = ''; checkIcon.style.display = 'none' }, 1200)
  })

  submitBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim()
    const pw = pwInput.value
    const hostname = getHostname()

    if (!username) { errEl.textContent = 'Username required'; errEl.style.display = 'block'; return }
    if (!pw) { errEl.textContent = 'Password required'; errEl.style.display = 'block'; return }
    if (!hostname) { errEl.textContent = 'hostname not set in config.json'; errEl.style.display = 'block'; return }

    const email = `${username}@${hostname}`
    const serverUrl = `https://${hostname}`

    submitBtn.disabled = true
    submitBtn.textContent = 'Generating…'
    errEl.style.display = 'none'

    try {
      // Build envelope client-side (Argon2id — takes a few seconds)
      const { envelope, authToken, kek } = await buildEnvelope(pw)

      submitBtn.textContent = 'Creating…'

      // Provision account on server
      const resp = await fetch(`${serverUrl}/account/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, envelope }),
      })
      if (!resp.ok) {
        const msg = resp.status === 409 ? 'Username taken' : `Server error (${resp.status})`
        errEl.textContent = msg
        errEl.style.display = 'block'
        submitBtn.textContent = 'Create'
        submitBtn.disabled = false
        return
      }

      submitBtn.textContent = 'Connecting…'

      // Use pre-computed authToken — no second Argon2id needed
      const stored = { serverUrl, email, password: authTokenToBasicAuth(authToken) }
      const session = await initSession(stored)
      if (!session) {
        errEl.textContent = 'Login failed after creation'
        errEl.style.display = 'block'
        submitBtn.textContent = 'Create'
        submitBtn.disabled = false
        return
      }

      const existing = loadStoredAccounts()
      if (!existing.some(a => a.email === email)) {
        saveStoredAccounts([...existing, stored])
      }
      addSession(session)
      initPGPForSession(session, kek)
      hideAccountCreateOverlay()
      refreshAccountsList()
      showSysMsg('Account created')
    } catch (e) {
      errEl.textContent = 'Error: ' + (e instanceof Error ? e.message : String(e))
      errEl.style.display = 'block'
      submitBtn.textContent = 'Create'
      submitBtn.disabled = false
    }
  })
}

export function randomHex4(): string {
  const arr = new Uint32Array(1)
  crypto.getRandomValues(arr)
  return (arr[0] & 0xffff).toString(16).padStart(4, '0')
}

export function showAccountCreateOverlay() {
  const overlay = document.getElementById('acc-create-overlay')
  if (overlay) overlay.style.display = 'flex'
  const hostnameEl = document.getElementById('acc-create-hostname')
  if (hostnameEl) hostnameEl.textContent = getHostname()
  const usernameInput = document.getElementById('acc-create-username') as HTMLInputElement
  if (usernameInput) usernameInput.value = randomHex4()
  const pwInput = document.getElementById('acc-create-password') as HTMLInputElement
  if (pwInput) { pwInput.value = generatePassphrase(); pwInput.focus() }
}

export function hideAccountCreateOverlay() {
  const overlay = document.getElementById('acc-create-overlay')
  if (overlay) overlay.style.display = 'none'
  ;(document.getElementById('acc-create-username') as HTMLInputElement).value = ''
  ;(document.getElementById('acc-create-password') as HTMLInputElement).value = ''
  const errEl = document.getElementById('acc-create-error')
  if (errEl) errEl.style.display = 'none'
  const submitBtn = document.getElementById('acc-create-submit') as HTMLButtonElement
  if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Create' }
}

export function showNewUserPage() {
  const page = document.getElementById('new-user-page')
  if (!page) return
  page.style.display = 'flex'
  try { history.replaceState(null, '', '#new') } catch {}
  const hostnameEl = document.getElementById('nu-hostname')
  if (hostnameEl) hostnameEl.textContent = getHostname()
  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  if (usernameInput) usernameInput.value = randomHex4()
  const pwInput = document.getElementById('nu-password') as HTMLInputElement
  if (pwInput) { pwInput.value = generatePassphrase(); pwInput.focus() }
}

function hideNewUserPage() {
  const page = document.getElementById('new-user-page')
  if (page) page.style.display = 'none'
}

export function setupNewUserPage() {
  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  const pwInput = document.getElementById('nu-password') as HTMLInputElement
  const submitBtn = document.getElementById('nu-submit') as HTMLButtonElement
  const errEl = document.getElementById('nu-error')!
  const copyBtn = document.getElementById('nu-pw-copy')!
  const copyIcon = document.getElementById('nu-copy-icon')!
  const checkIcon = document.getElementById('nu-check-icon')!
  const tosInput = document.getElementById('nu-tos') as HTMLInputElement
  const tosIcon = document.getElementById('nu-tos-icon')!

  tosInput.addEventListener('change', () => {
    tosIcon.style.opacity = tosInput.checked ? '1' : '0.3'
  })

  copyBtn.addEventListener('click', async () => {
    if (!pwInput.value) return
    await navigator.clipboard.writeText(pwInput.value)
    copyIcon.style.display = 'none'
    checkIcon.style.display = ''
    setTimeout(() => { copyIcon.style.display = ''; checkIcon.style.display = 'none' }, 1200)
  })

  submitBtn.addEventListener('click', async () => {
    const hostname = getHostname()
    const username = usernameInput.value.trim()
    const pw = pwInput.value

    if (!username) { errEl.textContent = 'Username required'; errEl.style.display = 'block'; return }
    if (!pw) { errEl.textContent = 'Password required'; errEl.style.display = 'block'; return }
    if (!hostname) { errEl.textContent = 'hostname not set in config.json'; errEl.style.display = 'block'; return }
    if (!tosInput.checked) { errEl.textContent = 'Please agree to the Terms of Beta-testing'; errEl.style.display = 'block'; return }

    const email = `${username}@${hostname}`
    // A home identity spans two relays: mail (jmapsmtp) and ActivityPub (jmapap).
    // Both must be provisioned with the same envelope so the identity anchor ties
    // them to one owner. (Provisioning only the apex left mail unprovisioned; on
    // reload migrateApexToMail rewrote the stored URL to the mail relay that had no
    // account → login failed / status went red.)
    const cfg = (window as any).__BISET_CONFIG__
    const mailUrl = (cfg?.mail_url || `https://mail.${hostname}`).replace(/\/$/, '')
    const apUrl = (cfg?.ap_url || `https://ap.${hostname}`).replace(/\/$/, '')

    submitBtn.disabled = true
    submitBtn.textContent = 'Generating…'
    errEl.style.display = 'none'

    try {
      const { envelope, authToken, kek, masterSecret } = await buildEnvelope(pw)
      const password = authTokenToBasicAuth(authToken)
      submitBtn.textContent = 'Creating…'

      // Root DID identity (DID.md Phase 1: mandatory from the first account).
      // Derived from the same masterSecret the envelope already carries — no
      // extra secret, no extra user step. Stored locally now; masterSecret
      // itself is discarded once this call returns.
      const { initDid } = await import('../did/index.ts')
      const didRecord = await initDid(email, masterSecret)

      // Provision both relays with the SAME envelope (+ did). The first claims the
      // identity anchor; the second presents the matching fingerprint/did and is
      // accepted, so the two relay accounts share one identity (username@hostname).
      const provision = (url: string) => fetch(`${url}/account/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, envelope, did: didRecord?.did }),
      })
      const relayFail = (label: string, status: number) => {
        errEl.textContent = status === 409 ? 'Username taken' : `${label} server error (${status})`
        errEl.style.display = 'block'
        submitBtn.textContent = 'Create'; submitBtn.disabled = false
      }
      const mailResp = await provision(mailUrl)
      if (!mailResp.ok) { relayFail('mail', mailResp.status); return }
      const apResp = await provision(apUrl)
      if (!apResp.ok) { relayFail('ap', apResp.status); return }

      submitBtn.textContent = 'Connecting…'
      const mailStored = { serverUrl: mailUrl, email, password }
      const apStored = { serverUrl: apUrl, email, password }
      const { initSession } = await import('../jmap/client.ts')
      const [mailSession, apSession] = await Promise.all([
        initSession(mailStored).catch(() => null),
        initSession(apStored).catch(() => null),
      ])
      if (!mailSession && !apSession) {
        errEl.textContent = 'Login failed after creation'; errEl.style.display = 'block'
        submitBtn.textContent = 'Create'; submitBtn.disabled = false
        return
      }

      const { loadStoredAccounts, saveStoredAccounts, addSession } = await import('../context.ts')
      const existing = loadStoredAccounts()
      const toAdd = [mailStored, apStored].filter(s =>
        !existing.some(a => a.email === s.email && a.serverUrl === s.serverUrl))
      if (toAdd.length) saveStoredAccounts([...existing, ...toAdd])

      const { initPGPForSession } = await import('../app.ts')
      // initPGPForSession no-ops on the AP relay (no PGP key store there).
      for (const s of [mailSession, apSession]) {
        if (s) { addSession(s); initPGPForSession(s, kek) }
      }

      hideNewUserPage()
      const { showApp, startPolling, showSysMsg } = await import('./shell.ts')
      showApp()
      const { setupLeftPane, refreshAccountsList, showMenuPage, openComposeTo } = await import('./left-pane.ts')
      await setupLeftPane()
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
      showMnemonic(masterSecret, { firstTime: true })
    } catch (e) {
      errEl.textContent = 'Error: ' + (e instanceof Error ? e.message : String(e))
      errEl.style.display = 'block'
      submitBtn.textContent = 'Create'; submitBtn.disabled = false
    }
  })
}
