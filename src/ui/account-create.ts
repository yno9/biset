// New-user onboarding (#new page) — username.apexDomain, mnemonic-only
// identity creation against identity/bootstrap.ts's createNewIdentity
// (did:webvh genesis + self-group join), replacing the pre-rewrite
// relay-provisioning flow (mail/AP account creation, DNS-anchor login
// detection, sign-key prerotation) entirely — none of that has an
// equivalent in the Vault-Core-only design (PLAN.md §7): an identity's mail
// address is *derived* from its domain (bootstrap.ts's mailFromForIdentity),
// never separately provisioned, and DIDComm provisions itself automatically
// at boot (main.ts's enableDidComm call).
//
// Restore-from-mnemonic (logging an existing identity into a new device) --
// reinstated 2026-08-26 after wrongly being called out of scope: the
// blocker this file's header used to describe (restoreIdentity's
// `deliveryFloorForNewDevice` has no safe default) only applies to adding
// an ADDITIONAL device alongside others already active (PCS/forward-secrecy
// -- a new device shouldn't retroactively decrypt vault content from before
// it joined). Restoring the identity's ONLY device after loss is a
// different case this rewrite's single-device-per-identity scope actually
// already covers: there is no other active device whose forward secrecy a
// full-history catch-up could violate, so starting from `deliverySeq(0n)` --
// the same floor createNewIdentity's own genesis path already uses -- is
// correct, not a shortcut. "Restore" means getting the whole vault back, not
// starting fresh.
//
// Detecting "does this address already exist" (src.bak's DNS-anchor lookup,
// did/discovery.ts, has no equivalent here) uses resolveByDomain directly
// instead: did:webvh resolution IS an HTTPS fetch of a well-known path
// (identity/webvh/resolver.ts), not a DNS TXT record, so checking existence
// needs no separate discovery mechanism at all -- the resolve itself IS the
// check (404/null = free, a document = already claimed).
import { IndexedDbIdentityRecordStore } from '../identity/record-store.ts'
import { createNewIdentity, restoreIdentity } from '../identity/bootstrap.ts'
import { resolveByDomain } from '../identity/webvh/resolver.ts'
import { readBisetConfig } from './config.ts'
import { encodeMultikey } from '../identity/webvh/multikey.ts'
import { ed25519 } from '@noble/curves/ed25519.js'

// Set once by main.ts (a plain function reference, not an import back to
// it) so the submit handler below can re-run the boot routine after
// creating an identity without importing main.ts itself. A dynamic
// `import('../main.ts')` here used to do this instead -- but main.ts is
// this bundle's own ENTRY POINT, and a module reachable both as the entry
// and via another module's import edge back into it makes bun's bundler
// wrap it in a lazy `__esm` initializer that nothing ever calls: the
// generated bundle defined `bootClient` but never invoked it, and the app
// silently never booted at all (found live, 2026-08-25 -- a totally blank
// page with no console error, since nothing had run yet to error).
let onIdentityCreated: ((reason: 'created' | 'restored') => Promise<void>) | undefined
export function setOnIdentityCreated(fn: (reason: 'created' | 'restored') => Promise<void>): void {
  onIdentityCreated = fn
}

export function randomHex4(): string {
  const arr = new Uint32Array(1)
  crypto.getRandomValues(arr)
  return (arr[0] & 0xffff).toString(16).padStart(4, '0')
}

// Everything opening #new does EXCEPT deciding where it's shown — shared by
// the inline mount on the account page (mountNewUserPageInline) and
// setupNewUserPage's one-time listener wiring.
function refreshNewUserPage(opts: { focus: boolean }) {
  const hostnameEl = document.getElementById('nu-hostname')
  if (hostnameEl) hostnameEl.textContent = readBisetConfig().apexDomain
  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  if (usernameInput) usernameInput.value = randomHex4()
  if (opts.focus) usernameInput?.focus()
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
  // No focus grab — this form shares the page with the account list, so
  // stealing the caret on every render would fight whatever the user was
  // actually doing.
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

// Both did:dht/did:webvh method-toggle buttons in the markup
// (nu-did-dht-btn/nu-did-webvh-btn) are inert: did:webvh is the only method
// this rewrite ever creates. Restore requires Root and current Sign phrases;
// in the initial generation both inputs intentionally contain Root phrase.

// setupNewUserPage is called from more than one route (main.ts's zero-
// identity boot branch) and route()-style re-entry would otherwise stack up
// duplicate listeners on a second call — guarded so a single submit fires
// its handler exactly once.
let _newUserPageWired = false

/** The #new submit button's resting label: signup until the typed address
 * turns out to already exist, at which point it's a login (src.bak's own
 * signupButtonLabel). */
function signupButtonLabel(loginDomain: string | null): string {
  return loginDomain ? 'Log in' : 'Start'
}

export function setupNewUserPage(): void {
  if (_newUserPageWired) return
  _newUserPageWired = true
  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  const submitBtn = document.getElementById('nu-submit') as HTMLButtonElement
  const errEl = document.getElementById('nu-error')!
  const tosInput = document.getElementById('nu-tos') as HTMLInputElement
  const tosIcon = document.getElementById('nu-tos-icon')!
  const phraseEl = document.getElementById('nu-phrase') as HTMLTextAreaElement | null
  const signPhraseEl = document.getElementById('nu-sign-phrase') as HTMLTextAreaElement | null

  tosInput.addEventListener('change', () => {
    tosIcon.style.opacity = tosInput.checked ? '1' : '0.3'
  })

  refreshNewUserPage({ focus: false })

  // ── "does this address already exist?" (src.bak's own DNS-anchor check,
  // done here via a direct resolve instead -- this file's header explains
  // why that's the equivalent, not a workaround). Debounced so typing
  // doesn't fire a resolve per keystroke; a domain that already resolves
  // flips this form into a login (phrase box appears, button relabels).
  let loginDomain: string | null = null
  let lookupSeq = 0
  let lookupTimer: ReturnType<typeof setTimeout> | null = null
  const applyLoginDetection = (domain: string | null) => {
    loginDomain = domain
    submitBtn.textContent = signupButtonLabel(loginDomain)
    if (phraseEl) {
      phraseEl.style.display = domain ? '' : 'none'
      if (!domain) phraseEl.value = ''
    }
    if (signPhraseEl) {
      signPhraseEl.style.display = domain ? '' : 'none'
      if (!domain) signPhraseEl.value = ''
    }
  }
  usernameInput.addEventListener('input', () => {
    // Optimistically back to signup the instant the name changes -- a
    // stale "Log in" on a name that no longer resolves would send the user
    // off looking for a recovery phrase for an address that isn't taken.
    applyLoginDetection(null)
    if (lookupTimer) clearTimeout(lookupTimer)
    const typed = usernameInput.value.trim()
    const { apexDomain } = readBisetConfig()
    if (!typed || !apexDomain) return
    const seq = ++lookupSeq
    lookupTimer = setTimeout(async () => {
      const domain = `${typed}.${apexDomain}`
      let exists = false
      try { exists = (await resolveByDomain(domain)) !== null } catch { /* offline / unreachable -- treat as free, the signup path */ }
      // Two staleness guards: `seq` catches a later lookup already in
      // flight, and the value comparison catches the field having moved on
      // (including refreshNewUserPage's programmatic reset, which fires no
      // input event).
      if (seq !== lookupSeq || usernameInput.value.trim() !== typed) return
      applyLoginDetection(exists ? domain : null)
    }, 400)
  })

  submitBtn.addEventListener('click', async () => {
    const { apexDomain, mimiSelfBaseUrl } = readBisetConfig()
    const username = usernameInput.value.trim()
    if (!username) { errEl.textContent = 'Username required'; errEl.style.display = 'block'; return }
    // apexDomain is the one thing genuinely always required; mimiSelfBaseUrl
    // is now the only Self/Vault membership path (the old Coordinator/core
    // Self Group route this used to fall back to has been retired entirely).
    if (!apexDomain) { errEl.textContent = 'apexDomain not set in config.json'; errEl.style.display = 'block'; return }
    if (!mimiSelfBaseUrl) { errEl.textContent = 'mimiSelfBaseUrl is not set in config.json -- Self Group cannot be established'; errEl.style.display = 'block'; return }

    // An existing address logs in instead of signing up -- checked BEFORE
    // the terms checkbox, same as src.bak: an existing identity already
    // agreed to them when it was created, re-gating an ordinary login
    // behind them again is nonsense.
    if (loginDomain) {
      const phrase = phraseEl?.value.trim() ?? ''
      if (!phrase) { errEl.textContent = `${loginDomain} already exists — paste its 24-word Root Key phrase to log in`; errEl.style.display = 'block'; phraseEl?.focus(); return }
      const signPhrase = signPhraseEl?.value.trim() ?? ''
      if (!signPhrase) { errEl.textContent = `${loginDomain} already exists — paste its current 24-word Sign Key phrase to log in`; errEl.style.display = 'block'; signPhraseEl?.focus(); return }
      submitBtn.disabled = true
      submitBtn.textContent = 'Logging in…'
      errEl.style.display = 'none'
      try {
        const recordStore = new IndexedDbIdentityRecordStore()
        try {
          await restoreIdentity(recordStore, { domain: loginDomain, mnemonic: phrase, signMnemonic: signPhrase })
        } finally {
          recordStore.close()
        }
        await onIdentityCreated?.('restored')
      } catch (e) {
        errEl.textContent = 'Log in failed: ' + (e instanceof Error ? e.message : String(e))
        errEl.style.display = 'block'
        submitBtn.textContent = signupButtonLabel(loginDomain)
        submitBtn.disabled = false
      }
      return
    }

    if (!tosInput.checked) { errEl.textContent = 'Please agree to the Terms of Beta-testing'; errEl.style.display = 'block'; return }

    submitBtn.disabled = true
    submitBtn.textContent = 'Creating…'
    errEl.style.display = 'none'

    try {
      const domain = `${username}.${apexDomain}`
      // Both recovery secrets must reach the user BEFORE genesis becomes
      // authoritative. Publishing first and then losing/closing the tab
      // between the two dialogs would create a permanently pre-rotated
      // identity whose first Spare Key was never recoverable.
      const masterSeed = crypto.getRandomValues(new Uint8Array(32))
      const spareSeed = crypto.getRandomValues(new Uint8Array(32))
      const { showMnemonic, showMnemonicOnce } = await import('./mnemonic.ts')
      const { seedToMnemonic } = await import('../identity/seed.ts')
      await new Promise<void>(resolve => {
        showMnemonic(masterSeed, { firstTime: true, onClose: resolve })
      })
      await showMnemonicOnce(seedToMnemonic(spareSeed), {
        firstTime: true,
        title: 'Spare Key',
        badges: ['SPARE KEY'],
        fingerprint: encodeMultikey(ed25519.getPublicKey(spareSeed)),
        subtitle: 'Keep this apart from the Root Key. It is required for the first key rotation and will become the next Sign Key.',
      })

      const recordStore = new IndexedDbIdentityRecordStore()
      // Closed immediately after use, success or failure -- this is a
      // throwaway, one-per-attempt instance (a retried signup after an
      // error creates a fresh one), and nothing downstream reuses it:
      // onIdentityCreated below triggers bootClient(), which opens its OWN
      // connection to this same database from scratch. Left open, each
      // attempt accumulated one more stale connection with nothing left
      // referencing it in this scope -- across enough retries in one tab,
      // that accumulation was enough to leave the browser's IndexedDB
      // implementation unable to complete even a brand-new open() at all
      // (found live, 2026-08-26, alongside main.ts's own logout() gap --
      // same underlying cause, two different leak sites).
      try {
        await createNewIdentity(recordStore, { domain, masterSeed, spareSeed })
      } finally {
        recordStore.close()
      }
      // No page navigation, same reasoning as logout (main.ts's own logout,
      // src.bak's original "no reload" fix): re-invoke the same boot routine
      // a real first load uses, now that an identity exists locally for it
      // to find -- via the callback main.ts registered (setOnIdentityCreated
      // above), never an import of main.ts itself.
      await onIdentityCreated?.('created')
    } catch (e) {
      errEl.textContent = 'Error: ' + (e instanceof Error ? e.message : String(e))
      errEl.style.display = 'block'
      submitBtn.textContent = 'Start'
      submitBtn.disabled = false
    }
  })
}
