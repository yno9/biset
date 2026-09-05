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
  completeDidMdWalletCallback,
  disconnectDidMdWallet,
  restoreDidMdWalletSession,
  type DidMdActiveSession,
} from '../wallet/did-md-oauth.ts'

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
let onWalletConnected: (() => Promise<void>) | undefined
export function setOnWalletConnected(fn: () => Promise<void>): void {
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
  const walletHandleEl = document.getElementById('nu-wallet-handle') as HTMLInputElement | null
  const walletLoginButton = document.getElementById('nu-wallet-login') as HTMLButtonElement | null
  const walletSessionEl = document.getElementById('nu-wallet-session') as HTMLDivElement | null
  const walletResultEl = document.getElementById('nu-wallet-result') as HTMLDivElement | null

  const walletResult = (message: string, error = false) => {
    if (!walletResultEl) return
    walletResultEl.textContent = message
    walletResultEl.style.display = 'block'
    walletResultEl.style.color = error ? '#ff3b30' : 'var(--text-dim)'
  }
  const showWalletSession = (session: DidMdActiveSession | undefined) => {
    if (!walletSessionEl) return
    walletSessionEl.replaceChildren()
    walletSessionEl.style.display = session ? 'flex' : 'none'
    if (!session) return
    const label = document.createElement('span')
    label.textContent = `Connected · ${session.handle} · device capability until ${new Date(session.capabilityExpiresAt).toLocaleDateString()}`
    const actions = document.createElement('span')
    actions.style.display = 'flex'; actions.style.gap = '6px'
    const disconnect = document.createElement('button')
    disconnect.type = 'button'; disconnect.textContent = 'Disconnect'; disconnect.style.cssText = 'border:0;background:transparent;color:var(--text-dim);font:inherit;cursor:pointer'
    disconnect.addEventListener('click', () => {
      void disconnectDidMdWallet().then(() => { showWalletSession(undefined); walletResult('This browser was disconnected. The remote capability remains revocable from did.md Wallet.') })
    })
    actions.append(disconnect)
    walletSessionEl.append(label, actions)
  }

  // A callback is consumed before ordinary session restore.  Its code is
  // one-use and the URL is cleared by the OAuth module after verification.
  void (async () => {
    try {
      const callback = await completeDidMdWalletCallback()
      const session = callback ?? await restoreDidMdWalletSession()
      if (session) {
        if (walletHandleEl) walletHandleEl.value = session.handle
        showWalletSession(session)
        walletResult(callback ? `Connected ${session.handle}. This browser can restore its DPoP-bound session without reopening Wallet.` : `Restored ${session.handle}'s DPoP-bound device session.`)
        await onWalletConnected?.()
      }
    } catch (error) {
      walletResult(error instanceof Error ? error.message : String(error), true)
    }
  })()

  walletLoginButton?.addEventListener('click', () => {
    const handle = walletHandleEl?.value ?? ''
    walletLoginButton.disabled = true
    walletResult('Verifying the published did:webvh log before opening did.md Wallet…')
    const config = readBisetConfig()
    // Safari allows a popup only while this click handler is active. The
    // authorization URL becomes available after asynchronous verification.
    const walletPopup = location.protocol === 'file:' ? window.open('', 'did-md-wallet') ?? undefined : undefined
    void beginDidMdWalletLogin(handle, config.mimiSelfBaseUrl, config.mediatorUrls, walletPopup).catch(error => {
      walletLoginButton.disabled = false
      walletResult(error instanceof Error ? error.message : String(error), true)
    })
  })
}
