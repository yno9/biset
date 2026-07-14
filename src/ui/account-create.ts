// New-user onboarding (#new page) — username@hostname + password
import { buildEnvelope } from '../cryptenv.ts'
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
      const { envelope, kek, masterSecret } = await buildEnvelope(pw)
      submitBtn.textContent = 'Creating…'

      // Root DID identity (DID.md Phase 1: mandatory from the first account).
      // Derived from the same masterSecret the envelope already carries.
      const { initDid } = await import('../did/index.ts')
      const didRecord = await initDid(email, masterSecret)
      const rootPriv = hexToBytes(didRecord!.rootPrivateKey)

      // Provision both home relays: signature-based DID binding + relay-scoped
      // token; own relays get the envelope (password recovery). Each relay logs
      // in with its OWN scoped token (res.password).
      const { provisionAccount } = await import('../did/provision.ts')
      const relayFail = (label: string, r: { conflict?: boolean; status: number }) => {
        errEl.textContent = r.conflict ? 'Username taken' : `${label} server error (${r.status})`
        errEl.style.display = 'block'
        submitBtn.textContent = 'Create'; submitBtn.disabled = false
      }
      const mailRes = await provisionAccount({ serverUrl: mailUrl, username, did: didRecord!.did, rootPrivateKey: rootPriv, masterSecret, envelope })
      if (!mailRes.ok) { relayFail('mail', mailRes); return }
      const apRes = await provisionAccount({ serverUrl: apUrl, username, did: didRecord!.did, rootPrivateKey: rootPriv, masterSecret, envelope })
      if (!apRes.ok) { relayFail('ap', apRes); return }

      submitBtn.textContent = 'Connecting…'
      // Each endpoint stores its OWN relay-scoped token.
      const mailStored = { serverUrl: mailUrl, email, password: mailRes.password!, did: didRecord?.did }
      const apStored = { serverUrl: apUrl, email, password: apRes.password!, did: didRecord?.did }
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

      // Publish the DID record to the new account's relay gateways (best-effort).
      import('../did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})
    } catch (e) {
      errEl.textContent = 'Error: ' + (e instanceof Error ? e.message : String(e))
      errEl.style.display = 'block'
      submitBtn.textContent = 'Create'; submitBtn.disabled = false
    }
  })

  // ── Recovery-phrase login ──────────────────────────────────────────────────
  // 24 words → seed → DID → resolve relays → connect. No password, no need to
  // know your relays/address (the DID document supplies them). See did/restore.ts.
  const restoreToggle = document.getElementById('nu-restore-toggle')
  const restoreBox = document.getElementById('nu-restore-box')
  const restorePhrase = document.getElementById('nu-restore-phrase') as HTMLTextAreaElement | null
  const restoreSubmit = document.getElementById('nu-restore-submit') as HTMLButtonElement | null
  const restoreErr = document.getElementById('nu-restore-error')
  restoreToggle?.addEventListener('click', () => {
    if (!restoreBox) return
    const open = restoreBox.style.display === 'flex'
    restoreBox.style.display = open ? 'none' : 'flex'
    if (!open) restorePhrase?.focus()
  })
  restoreSubmit?.addEventListener('click', async () => {
    if (!restorePhrase || !restoreErr) return
    const phrase = restorePhrase.value.trim()
    if (!phrase) { restoreErr.textContent = 'Enter your recovery phrase'; restoreErr.style.display = 'block'; return }
    restoreErr.style.display = 'none'
    restoreSubmit.disabled = true; restoreSubmit.textContent = 'Restoring…'
    try {
      const { restoreFromMnemonic } = await import('../did/restore.ts')
      const res = await restoreFromMnemonic(phrase)
      if ('error' in res) { restoreErr.textContent = res.error; restoreErr.style.display = 'block'; return }
      const { addSession, loadStoredAccounts, saveStoredAccounts } = await import('../context.ts')
      const { initPGPForSession } = await import('../app.ts')
      const existing = loadStoredAccounts()
      const toAdd = res.sessions.map(s => s.account).filter(a => !existing.some(x => x.email === a.email && x.serverUrl === a.serverUrl))
      if (toAdd.length) saveStoredAccounts([...existing, ...toAdd])
      for (const s of res.sessions) { addSession(s); initPGPForSession(s, res.kek) }
      hideNewUserPage()
      const { showApp, startPolling, showSysMsg } = await import('./shell.ts')
      showApp()
      const { setupLeftPane, refreshAccountsList, showMenuPage } = await import('./left-pane.ts')
      await setupLeftPane(); startPolling(); refreshAccountsList(); showMenuPage('/account')
      showSysMsg('Identity restored')
      import('../did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})
    } catch (e) {
      restoreErr.textContent = 'Restore failed: ' + (e instanceof Error ? e.message : String(e))
      restoreErr.style.display = 'block'
    } finally {
      restoreSubmit.disabled = false; restoreSubmit.textContent = 'Restore'
    }
  })
}
