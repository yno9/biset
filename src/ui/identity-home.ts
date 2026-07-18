// The home screen for a relay-less identity (DID⊥relay orthogonality). A DID
// created without any relay account has no inbox and no session — the normal app
// shell assumes sessions[], so this is its own minimal surface: show who you are
// (the DID), your only backup (the recovery phrase), and the one action that
// turns this into a full account — adding a relay (Phase B).
import { hexToBytes } from '../utils.ts'
import { deriveRootKey, didFromRootPublicKey } from '../did/keys.ts'
import { mnemonicToSeed, isValidMnemonic } from '../did/seed.ts'
import { getDidRecord } from '../did/store.ts'
import { clearStandalone } from '../did/create-standalone.ts'

const OVERLAY_ID = 'identity-home-page'

function shortDid(did: string): string {
  const body = did.replace(/^did:dht:/, '')
  return `did:dht:${body.slice(0, 8)}…${body.slice(-6)}`
}

/** Render the relay-less identity home. masterSeed is passed straight after
 * creation (so "show recovery phrase" and "add relay" work without re-entry);
 * on a returning boot it is absent and those actions ask for the phrase. */
export async function showIdentityHome(did: string, masterSeed?: Uint8Array): Promise<void> {
  document.getElementById(OVERLAY_ID)?.remove()
  const page = document.createElement('div')
  page.id = OVERLAY_ID
  page.style.cssText = 'position:fixed;inset:0;background:var(--bg);display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px;z-index:10;gap:16px'
  page.innerHTML = `
    <div style="font-size:15px;font-weight:600;color:var(--text)">Your identity</div>
    <div id="ih-did" style="font-family:monospace;font-size:13px;color:var(--text-dim);cursor:pointer;user-select:all"></div>
    <div style="max-width:340px;text-align:center;font-size:13px;color:var(--text-dim);line-height:1.5">
      This identity lives on no relay yet — it is reachable only through the
      mediator. Your <b>recovery phrase is the only backup</b>: without a relay
      there is no password reset.
    </div>
    <button id="ih-phrase" style="padding:10px 16px;border-radius:8px;border:1px solid var(--header-border);background:var(--input-bg);color:var(--text);font-size:14px;cursor:pointer">Show recovery phrase</button>
    <div id="ih-addrelay-box" style="display:flex;flex-direction:column;gap:8px;align-items:center;width:100%;max-width:340px">
      <button id="ih-addrelay" style="padding:10px 16px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-size:15px;font-weight:500;cursor:pointer;width:100%">Add a relay (get an address)</button>
    </div>
    <div id="ih-error" style="color:#ff3b30;font-size:13px;display:none;min-height:18px;text-align:center"></div>`
  document.body.appendChild(page)

  const didEl = page.querySelector('#ih-did') as HTMLElement
  didEl.textContent = shortDid(did) // did is self-derived z-base32; set as text, never HTML
  didEl.title = did

  const err = page.querySelector('#ih-error') as HTMLElement
  const showErr = (m: string) => { err.textContent = m; err.style.display = 'block' }

  page.querySelector('#ih-did')?.addEventListener('click', () => {
    navigator.clipboard?.writeText(did).catch(() => {})
  })

  // Resolve the master seed on demand: in-hand after creation, otherwise ask for
  // the recovery phrase and confirm it derives THIS did (never a stranger's).
  const getSeed = async (): Promise<Uint8Array | null> => {
    if (masterSeed) return masterSeed
    const phrase = prompt('Enter your 24-word recovery phrase')
    if (!phrase) return null
    if (!isValidMnemonic(phrase)) { showErr('Invalid recovery phrase'); return null }
    const seed = mnemonicToSeed(phrase)
    if (didFromRootPublicKey(deriveRootKey(seed).publicKey) !== did) {
      showErr('That phrase belongs to a different identity'); return null
    }
    return seed
  }

  page.querySelector('#ih-phrase')?.addEventListener('click', async () => {
    err.style.display = 'none'
    const seed = await getSeed()
    if (!seed) return
    const { showMnemonic } = await import('./mnemonic.ts')
    showMnemonic(seed, { firstTime: false })
  })

  page.querySelector('#ih-addrelay')?.addEventListener('click', async () => {
    err.style.display = 'none'
    const seed = await getSeed()
    if (!seed) return
    const username = (prompt('Choose a username for this relay') || '').trim().toLowerCase()
    if (!username) return
    const btn = page.querySelector('#ih-addrelay') as HTMLButtonElement
    btn.disabled = true; btn.textContent = 'Adding…'
    try {
      await addRelaysToIdentity(did, seed, username)
      page.remove()
    } catch (e) {
      showErr('Error: ' + (e instanceof Error ? e.message : String(e)))
      btn.disabled = false; btn.textContent = 'Add a relay (get an address)'
    }
  })
}

/** Phase B: bind an existing relay-less DID to the deployment's home relays
 * (mail + ap), turning it into a normal multi-relay account. Mirrors the #new
 * flow's provision→session→store→showApp, but reuses the DID that already
 * exists instead of minting one, and carries no envelope (a standalone identity
 * has no password to recover — the mnemonic is its recovery path). */
async function addRelaysToIdentity(did: string, masterSeed: Uint8Array, username: string): Promise<void> {
  const rec = await getDidRecord(did)
  if (!rec) throw new Error('identity record missing')
  const rootPriv = hexToBytes(rec.rootPrivateKey)
  const cfg = (window as any).__BISET_CONFIG__ || {}
  const hostname: string = cfg.hostname || ''
  const mailUrl = (cfg.mail_url || `https://mail.${hostname}`).replace(/\/$/, '')
  const apUrl = (cfg.ap_url || `https://ap.${hostname}`).replace(/\/$/, '')
  const email = `${username}@${hostname}`

  const { provisionAccount } = await import('../did/provision.ts')
  const mailRes = await provisionAccount({ serverUrl: mailUrl, username, did, rootPrivateKey: rootPriv, masterSecret: masterSeed })
  if (!mailRes.ok) throw new Error(mailRes.conflict ? 'Username taken' : `mail relay error (${mailRes.status})`)
  const apRes = await provisionAccount({ serverUrl: apUrl, username, did, rootPrivateKey: rootPriv, masterSecret: masterSeed })
  if (!apRes.ok) throw new Error(apRes.conflict ? 'Username taken' : `ap relay error (${apRes.status})`)

  const mailStored = { serverUrl: mailUrl, email, password: mailRes.password!, did }
  const apStored = { serverUrl: apUrl, email, password: apRes.password!, did }
  const { initSession } = await import('../jmap/client.ts')
  const [mailSession, apSession] = await Promise.all([
    initSession(mailStored).catch(() => null),
    initSession(apStored).catch(() => null),
  ])
  if (!mailSession && !apSession) throw new Error('Login failed after provisioning')

  const { loadStoredAccounts, saveStoredAccounts, addSession } = await import('../context.ts')
  const existing = loadStoredAccounts()
  const toAdd = [mailStored, apStored].filter(s => !existing.some(a => a.email === s.email && a.serverUrl === s.serverUrl))
  if (toAdd.length) saveStoredAccounts([...existing, ...toAdd])

  const { initPGPForSession } = await import('../app.ts')
  for (const s of [mailSession, apSession]) if (s) { addSession(s); initPGPForSession(s) }

  // No longer relay-less: drop the standalone marker so future boots go through
  // the normal session path.
  clearStandalone()

  const { showApp, startPolling, showSysMsg } = await import('./shell.ts')
  showApp()
  const { setupLeftPane, refreshAccountsList, showMenuPage } = await import('./left-pane.ts')
  await setupLeftPane(); startPolling(); refreshAccountsList(); showMenuPage('/account')
  showSysMsg('Relay added')
  // Republish the DID document — now WITH the relays' services (publishOwnDids
  // reads live sessions), on top of the mediator service already registered.
  import('../did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})
}
