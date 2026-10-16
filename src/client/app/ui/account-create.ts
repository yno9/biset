// New-user onboarding (#new page). Since N1 (2026-09-05) this file has one
// job only: the did.md Wallet login. The native BIP39 path it used to own
// -- `username.apexDomain` + 24-word Root/Sign phrases, driving
// identity/bootstrap.ts's createNewIdentity/restoreIdentity -- has been
// removed outright, together with its markup in index.html and the
// did:webvh genesis machinery behind it. did.md is the identity issuer now;
// biset never mints, restores, or holds a controller key of its own.
import { readBisetConfig } from './config.ts'
import {
  beginDidMdWalletLogin,
  prepareDidMdWalletLoginRequest,
  completeDidMdWalletCallback,
  restoreDidMdWalletSession,
  resolveWalletFromSuffix,
  selectWallet,
  currentWallet,
  type DidMdActiveSession,
} from '../../identity/wallet/did-md-oauth.ts'
import { WALLET_DIRECTORY } from '../../identity/wallet/wallet-directory.ts'
import { ditoEmbedOrigin, mountDito, type DitoEmbed } from '../../identity/wallet/dito-embed.ts'

// Set once by main.ts (a plain function reference, not an import back to
// it) so the handler below can re-run the boot routine after a Wallet
// session appears without importing main.ts itself. A dynamic
// `import('../main.ts')` here used to do this instead -- but main.ts is
// this bundle's own ENTRY POINT, and a module reachable both as the entry
// and via another module's import edge back into it makes bun's bundler
// wrap it in a lazy `__esm` initializer that nothing ever calls: the
// generated bundle defined `bootClient` but never invoked it, and the app
// silently never booted at all (found live, 2026-08-25 -- a totally blank
// page with no console error, since nothing had run yet to error).
let onWalletConnected: ((session: DidMdActiveSession) => Promise<void>) | undefined
export function setOnWalletConnected(fn: (session: DidMdActiveSession) => Promise<void>): void {
  onWalletConnected = fn
}

// ── Inline mount on the account page (2026-08-12, user-requested; the only
// way #new is shown at all — #account owns account creation entirely) ──
// With zero identities, #account shows this signup form in place of a bare
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
  // scrolls instead of clipping the form.
  const centered = opts.centered ?? true
  page.setAttribute('style', centered
    ? 'display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:calc(100vh - 220px);padding:4px 0 20px'
    : 'display:flex;flex-direction:column;align-items:center;padding:4px 0 20px')
  // The "biset / beta" masthead belongs to a full-page takeover; inside the
  // account page it's a second app title under the one already on screen.
  const title = page.querySelector<HTMLElement>('.biset-title')
  if (title) title.style.display = 'none'
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

// setupNewUserPage is called from more than one route (main.ts's zero-
// identity boot branch) and route()-style re-entry would otherwise stack up
// duplicate listeners on a second call — guarded so a single click fires
// its handler exactly once.
let _newUserPageWired = false

export function setupNewUserPage(): void {
  if (_newUserPageWired) return
  _newUserPageWired = true
  const walletLoginButton = document.getElementById('nu-wallet-login') as HTMLButtonElement | null
  const walletResultEl = document.getElementById('nu-wallet-result') as HTMLDivElement | null

  // PLAN4 (~/did.md/PLAN4-wallet-connector.md): "connect with [...]" -- the
  // [...] is WALLET_DIRECTORY, not a hardcoded dito assumption. With one
  // entry (today), no picker renders and the button behaves exactly as
  // before -- zero UX change until the directory actually grows.
  if (walletLoginButton && WALLET_DIRECTORY.length > 1) {
    const picker = document.createElement('select')
    picker.id = 'nu-wallet-picker'
    picker.style.cssText = 'margin-right:8px;padding:8px 10px;border-radius:8px;font:inherit;font-size:14px'
    for (const entry of WALLET_DIRECTORY) {
      const option = document.createElement('option')
      option.value = entry.id; option.textContent = entry.displayName
      if (entry.id === currentWallet().id) option.selected = true
      picker.append(option)
    }
    picker.addEventListener('change', () => {
      const entry = WALLET_DIRECTORY.find(candidate => candidate.id === picker.value)
      if (entry) selectWallet(entry)
    })
    walletLoginButton.before(picker)
  }

  // Optional: resolve a wallet by did:webvh suffix (e.g. "alice.did.md")
  // instead of picking from WALLET_DIRECTORY -- the same "log in with your
  // own identity's own issuer" pattern atproto uses for PDS discovery
  // (its DID document's #atproto_pds entry), applied to wallet discovery.
  // Left empty, login behaves exactly as before: WALLET_DIRECTORY's
  // selected entry (dito by default).
  let suffixInput: HTMLInputElement | undefined
  if (walletLoginButton) {
    suffixInput = document.createElement('input')
    suffixInput.type = 'text'
    suffixInput.id = 'nu-wallet-suffix'
    suffixInput.placeholder = 'your did:web suffix (optional)'
    suffixInput.autocomplete = 'off'
    suffixInput.style.cssText = 'margin-right:8px;padding:8px 10px;border-radius:8px;font:inherit;font-size:14px;width:200px'
    walletLoginButton.before(suffixInput)
  }

  const walletResult = (message: string, error = false) => {
    if (!walletResultEl) return
    walletResultEl.textContent = message
    walletResultEl.style.display = 'block'
    walletResultEl.style.overflowWrap = 'anywhere'
    walletResultEl.style.color = error ? '#ff3b30' : 'var(--text-dim)'
  }
  // A callback is consumed before ordinary session restore.  Its code is
  // one-use and the URL is cleared by the OAuth module after verification.
  void (async () => {
    try {
      const callback = await completeDidMdWalletCallback()
      const session = callback ?? await restoreDidMdWalletSession()
      if (session) {
        await onWalletConnected?.(session)
      }
    } catch (error) {
      walletResult(error instanceof Error ? error.message : String(error), true)
    }
  })()

  // Same-site with dito: create the identity from dito's own form (an iframe),
  // in place of the popup login button.
  const ditoOrigin = ditoEmbedOrigin()
  const createBox = document.getElementById('nu-create') as HTMLDivElement | null
  const createFrame = document.getElementById('nu-dito-frame') as HTMLIFrameElement | null
  // The wallet callback page finishes a sign-in; it has no create form to show.
  if (ditoOrigin && createBox && createFrame && location.pathname !== '/wallet/callback') {
    createBox.style.display = 'flex'
    document.getElementById('nu-wallet-login-row')?.style.setProperty('display', 'none')
    // Nothing on this page may move while the wallet works: the happy path shows no
    // message at all (an "already has" / "created" line pushed the form up and down).
    // Only a failure is reported.
    // Sign-in rides along with the creation, in the background: the signed request is prepared the
    // moment Create is pressed (so nothing waits for it), handed to dito's save page, which approves
    // it while the person saves the Passphrase, and the response lands on /wallet/callback.
    let loginRequest: Promise<string | undefined> | undefined
    let ditoEmbed: DitoEmbed | undefined
    mountDito(createFrame, ditoOrigin, 'create', {
      // An existing identity: dito's frame collects the Passphrase and signs in itself; this page
      // only prepares the signed request and takes the response, so the wallet is never left.
      login: handle => {
        void (async () => {
          const config = readBisetConfig()
          // The frame reports its own failures (wrong Passphrase, ...); only ours are shown here.
          const request = await prepareDidMdWalletLoginRequest(config.mediatorUrls, config, handle)
          const response = await ditoEmbed!.approve(request).catch(() => undefined)
          if (!response) return
          const session = await completeDidMdWalletCallback(response)
          if (!session) return
          await onWalletConnected?.(session)
        })().catch(error => {
          void ditoEmbed?.cancel().catch(() => {})
          walletResult(error instanceof Error ? error.message : String(error), true)
        })
      },
      creating: handle => {
        const config = readBisetConfig()
        loginRequest = prepareDidMdWalletLoginRequest(config.mediatorUrls, config, handle).catch(error => {
          console.warn('[did.md Wallet login] could not prepare the sign-in request; the identity is still created', error instanceof Error ? error.message : error)
          return undefined
        })
      },
      created: () => {},
      // The same tab goes to dito's top-level save page and comes back: to the wallet callback
      // when the sign-in succeeded, otherwise to this very URL.
      savePage: async () => {
        const login = await loginRequest
        const target = `${ditoOrigin}/?embed=save&return=${encodeURIComponent(location.href)}${login ? `&login=${encodeURIComponent(login)}` : ''}`
        location.assign(target)
      },
      // Nothing to do here: the frame itself opens on the log-in form for the identity this browser holds.
      existing: () => {},
      unloaded: () => {},
      error: message => walletResult(message, true),
    }).then(embed => { ditoEmbed = embed }).catch(error => walletResult(error instanceof Error ? error.message : String(error), true))
  }

  walletLoginButton?.addEventListener('click', () => {
    walletLoginButton.disabled = true
    // Safari only permits opening a window in the original click handler --
    // reserve it now, before the asynchronous suffix resolution below, the
    // same reason redirectToWallet itself takes an already-opened popup.
    const popup = location.protocol === 'file:' ? window.open('', 'did-md-wallet') ?? undefined : undefined
    const config = readBisetConfig()
    const suffix = suffixInput?.value.trim()
    void (async () => {
      if (suffix) {
        walletResult(`Resolving ${suffix}…`)
        selectWallet(await resolveWalletFromSuffix(suffix))
      }
      walletResult('Opening did.md Wallet…')
      await beginDidMdWalletLogin(config.mediatorUrls, popup, config)
    })().catch(error => {
      walletLoginButton.disabled = false
      walletResult(error instanceof Error ? error.message : String(error), true)
    })
  })
}
