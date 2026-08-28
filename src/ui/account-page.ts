// Port of src.bak/ui/left-pane.ts's #account page. Per user direction
// (2026-08-24), PAGE_HTML below is the ORIGINAL renderAccountPage() markup
// verbatim -- every element it had, nothing trimmed for looking
// unfinished, including pieces this rewrite can't wire up yet (identity
// menu button, #cmd-acc-list, #cmd-acc-compose-fab, the devices list).
// Only the DATA behind it is cut down to what this rewrite's single-
// identity/single-local-vault model actually has:
//
//   - avatar/name/DID/copy: real.
//   - the expandable panel's DID document half is real too --
//     identity/webvh/resolver.ts's resolve() is the same resolution this
//     rewrite's own bootstrap already trusts, so "click to view devices and
//     DID document" now actually fetches and shows the live document.
//   - the devices list stays empty (no device-roster read API wired to the
//     UI yet), and #cmd-acc-list has no click handler (multi-relay accounts
//     have no corresponding backend or concept here at all yet) -- present
//     in the DOM, inert for now, same as every other not-yet-wired element
//     left-pane.ts's own header notes. The identity menu button IS wired
//     (identityMenuItems below) -- Log out is real, the rest of that menu's
//     items stay inert the same way.
//   - #cmd-acc-compose-fab WAS left inert too (2026-08-24), on the
//     assumption the left pane's own #lp-compose-fab was the one real
//     compose entry point -- wrong once showAccountPage() became the actual
//     landing page after signup/boot with no session yet (main.ts's own
//     2026-08-25 fix): that made this fab the ONLY compose entry point
//     visible at that moment, and "the pencil icon does nothing" was the
//     result (found live). Wired the same way #lp-compose-fab already is.
import { render } from './thread.ts'
import { esc, avatarStyle } from './format.ts'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { resolveWithRouting } from '../didcomm/webvh-resolve.ts'
import { shortWebvhDid } from './did-display.ts'
import { showComposePage } from './compose-page.ts'
import { mountNewUserPageInline, unmountNewUserPageInline, setupNewUserPage } from './account-create.ts'
import { isPreRotationActive, currentNextKeyHashes } from '../identity/webvh/prerotation.ts'
import { showMnemonic, showMnemonicOnce, promptForMnemonic } from './mnemonic.ts'
import { fromHex } from '../identity/bootstrap.ts'
import { seedToMnemonic, mnemonicToSeed } from '../identity/seed.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { encodeMultikey } from '../identity/webvh/multikey.ts'
import { multikeyHashBase58 } from '../identity/webvh/hash.ts'

export interface AccountPageConfig {
  /** null before any local identity exists yet -- the account page is
   * src.bak's ACTUAL default/landing page for that state too (main.ts's own
   * `if (!sessions.length) showMenuPage('/account')`, and `#new`/`#restore`
   * being retired hashes that just redirect here), not a separate
   * `#new-user-page` overlay. This rewrite had drifted into showing that
   * overlay directly instead (2026-08-25, corrected after user feedback) --
   * `did: null` is what tells showAccountPage() to mount the signup form
   * inline (mountNewUserPageInline) in place of the identity card, matching
   * that design exactly rather than inventing a "default page is the inbox"
   * model this rewrite never actually had. */
  did: string | null
  /** This device's own MLS device kid (identity/bootstrap.ts's
   * IdentityRecord.deviceKid) -- labels the matching row in the devices
   * list as "(this device)" once it resolves. */
  deviceKid?: string
  /** hex (identity/record-store.ts's IdentityRecord.masterSeed) -- the ONE
   * piece of key material this file is handed directly rather than through
   * a callback: showing the Root Key phrase on demand (the Config modal's
   * click-to-reveal row) has to happen in the UI layer regardless (same as
   * account-create.ts's own initial showMnemonic call at signup), so there
   * is no "stays in main.ts" boundary to preserve here the way there is
   * for editName/revokeDevice, which never need to look at key material at
   * all. */
  masterSeed?: string
  /** Confirmed and invoked by the identity menu's "Log out" item
   * (src.bak/ui/left-pane.ts's confirmAndLogout -- confirm() stays here in
   * the UI layer, this is just the "actually do it" half). */
  onLogout?(): Promise<void>
  /** Signs and publishes a new self-asserted display name (routing.json's
   * `name`, didcomm/webvh-routing.ts's setRoutingName) -- main.ts's own
   * closure, since it holds the root key this needs to sign with; this file
   * never sees key material. */
  onEditName?(name: string): Promise<void>
  /** Revokes a DIFFERENT device from this identity's self group (MLS
   * removal + DID document verificationMethod removal, main.ts's own
   * closure -- same key-material-stays-in-main.ts reasoning as onEditName).
   * Never offered for the current device's own row (see the devices-list
   * render below) -- self-revoke is what logout already is. */
  onRevokeDevice?(targetDeviceKid: string): Promise<void>
  /** Turns pre-rotation on (identity/webvh/prerotation.ts's
   * activatePreRotation), signed with the Root Key that stays in main.ts.
   * `nextKeyHash` is computed here from a freshly generated Spare Key that
   * this file generates, displays once, and never hands over raw. */
  onActivateKeyRotation?(nextKeyHash: string): Promise<void>
  /** Reveals the current Spare Key (typed in by the user, this file's own
   * promptForMnemonic) to rotate to a new one — main.ts combines it with
   * the Root Key's public half for the entry's fallback-authority field. */
  onRotateKeyRotation?(revealedPrivateKey: Uint8Array, revealedPublicKey: Uint8Array, nextKeyHash: string): Promise<void>
  /** Same reveal, but turns pre-rotation back off and returns update
   * authority to the Root Key. */
  onDeactivateKeyRotation?(revealedPrivateKey: Uint8Array, revealedPublicKey: Uint8Array): Promise<void>
  /** Moves this identity to a new domain (identity/webvh/move.ts's
   * moveWebvhIdentity) -- main.ts's own closure, since it holds the root
   * key (and, if this device has a self group, the MLS leaf key) this
   * needs to sign with. Resolves to the new did on success. */
  onMoveIdentity?(newDomain: string): Promise<string>
  /** Starts the user-gesture-bound OpenID4VP + OIDC PKCE popup flow. */
  onConnectCoordinator?(): Promise<void>
  onCreateCoordinatorInvitation?(): Promise<{ invitation: string; expiresAt: string }>
  onJoinCoordinatorInvitation?(invitation: string): Promise<void>
  onResumeCoordinatorJoin?(): Promise<void>
  onApproveCoordinatorDevice?(): Promise<void>
  /** src.bak's showSysMsg (shell.ts) -- injected rather than imported
   * directly: shell.ts -> left-pane.ts -> account-page.ts already, so an
   * import the other way round would close a cycle (main.ts hit the same
   * shape of bug with bootClient itself, 2026-08-25). Used for the DID-copy
   * toast (wireIdentityDid's own "DID copied"). */
  showMessage?(text: string): void
}

let config: AccountPageConfig | undefined
let active = false
let configPageActive = false

export function configureAccountPage(next: AccountPageConfig): void {
  config = next
}

export function inAccountMode(): boolean {
  return active
}

export function inConfigMode(): boolean {
  return configPageActive
}

// ── identity menu (dropdown) ────────────────────────────────────────────────
// Ported from src.bak/ui/left-pane.ts's openDropdownMenu/closeAccountMenu --
// anchored below-right of the button, closes on outside click/Escape.
interface MenuItem { label: string; danger?: boolean; onClick: () => void }

let openMenuCleanup: (() => void) | null = null

function closeIdentityMenu(): void {
  openMenuCleanup?.()
  openMenuCleanup = null
}

function openDropdownMenu(anchor: HTMLElement, items: MenuItem[]): void {
  closeIdentityMenu()
  const rect = anchor.getBoundingClientRect()
  const menu = document.createElement('div')
  menu.style.cssText = `position:fixed;top:${rect.bottom + 4}px;left:${Math.max(8, rect.right - 180)}px;width:180px;background:var(--bg);border:1px solid var(--border, rgba(128,128,128,0.25));border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,0.18);z-index:10000;padding:4px;font-size:14px`
  for (const item of items) {
    const b = document.createElement('button')
    b.type = 'button'
    b.style.cssText = `display:block;width:100%;text-align:left;padding:8px 12px;background:none;border:none;border-radius:6px;cursor:pointer;color:${item.danger ? '#ff3b30' : 'var(--text)'};font-size:14px`
    b.textContent = item.label
    b.addEventListener('mouseover', () => { b.style.background = 'rgba(128,128,128,0.12)' })
    b.addEventListener('mouseout', () => { b.style.background = 'none' })
    b.addEventListener('click', () => { closeIdentityMenu(); item.onClick() })
    menu.appendChild(b)
  }
  document.body.appendChild(menu)
  const onDocClick = (ev: MouseEvent) => {
    if (!menu.contains(ev.target as Node)) closeIdentityMenu()
  }
  const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape') closeIdentityMenu() }
  setTimeout(() => document.addEventListener('click', onDocClick), 0)
  document.addEventListener('keydown', onKey)
  openMenuCleanup = () => {
    document.removeEventListener('click', onDocClick)
    document.removeEventListener('keydown', onKey)
    menu.remove()
  }
}

// ── Generic modal (src.bak's own openModal, verbatim) ───────────────────────
function openModal(title: string, bodyEl: HTMLElement, onClose?: () => void): () => void {
  const overlay = document.createElement('div')
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:10001;display:flex;align-items:center;justify-content:center;padding:16px'
  const box = document.createElement('div')
  box.style.cssText = 'background:var(--bg);color:var(--text);border-radius:12px;padding:20px;max-width:420px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.3);max-height:90vh;overflow:auto'
  const header = document.createElement('div')
  header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:16px'
  const h = document.createElement('h3')
  h.textContent = title
  h.style.cssText = 'margin:0;font-size:16px'
  const close = document.createElement('button')
  close.type = 'button'
  close.textContent = '✕'
  close.style.cssText = 'background:none;border:none;color:var(--text-dim);font-size:20px;cursor:pointer;padding:0 4px'
  const dismiss = () => {
    document.removeEventListener('keydown', onKey)
    onClose?.()
    overlay.remove()
  }
  const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape') dismiss() }
  document.addEventListener('keydown', onKey)
  close.addEventListener('click', dismiss)
  overlay.addEventListener('click', ev => { if (ev.target === overlay) dismiss() })
  header.append(h, close)
  box.append(header, bodyEl)
  overlay.appendChild(box)
  document.body.appendChild(overlay)
  return dismiss
}

/** src.bak's openDisplayNameModal, narrowed: no relay/JMAP Identity write
 * (setLocalDisplayName/applyDisplayNameToRelay -- this rewrite has no
 * per-relay Identity concept), no mediator-gated republish side effect
 * (this rewrite's routing.json IS the one place a name lives, always
 * current the moment onEditName resolves, not something a separate publish
 * step catches up on later). Reachable from the name text/pencil icon
 * directly, same as src.bak's `identityName.onclick` -- NOT only via the
 * identity menu's own "Edit identity" item (found live, 2026-08-26: the
 * pencil icon did nothing because only the menu was wired). */
function openDisplayNameModal(did: string, currentName: string): void {
  if (!config?.onEditName) return
  const body = document.createElement('form')
  body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
  body.innerHTML = `
    <div style="font-size:12px;color:var(--text-dim)">${esc(did)}</div>
    <input class="cmd-input" type="text" name="name" value="${esc(currentName)}" placeholder="Display name" required autofocus>
    <div data-role="error" style="color:#ff3b30;font-size:12px;display:none"></div>
    <div data-role="ok" style="color:#34c759;font-size:12px;display:none"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px">
      <button type="button" data-role="cancel" class="cmd-page-btn" style="width:auto;padding:6px 14px">Cancel</button>
      <button type="submit" data-role="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 14px">Save</button>
    </div>`
  const dismiss = openModal('Change display name', body)
  body.querySelector<HTMLButtonElement>('[data-role=cancel]')!.addEventListener('click', dismiss)
  body.addEventListener('submit', async ev => {
    ev.preventDefault()
    const newName = (body.elements.namedItem('name') as HTMLInputElement).value.trim()
    const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
    const okEl = body.querySelector<HTMLElement>('[data-role=ok]')!
    const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
    errEl.style.display = 'none'; okEl.style.display = 'none'
    if (!newName) { errEl.textContent = 'Display name required'; errEl.style.display = 'block'; return }
    submit.disabled = true; submit.textContent = 'Saving…'
    try {
      await config!.onEditName!(newName)
      const identityNameEl = document.getElementById('cmd-acc-identity-name')
      if (identityNameEl) identityNameEl.textContent = newName
      okEl.textContent = 'Saved'; okEl.style.display = 'block'
      setTimeout(dismiss, 600)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : 'Save failed'
      errEl.style.display = 'block'
    } finally {
      submit.disabled = false; submit.textContent = 'Save'
    }
  })
}

/** Ported from src.bak/did/webvh/publish.ts's own availability check
 * (via src.bak/ui/edit-identity.ts's checkAvailability), narrowed to
 * domain only -- this rewrite's did:webvh has no username path segment
 * (subdomain-per-identity, identity/webvh/identifier.ts), so there is no
 * separate axis to check. GET the candidate domain's own did.jsonl: 404 is
 * available, 200 with a different SCID in its first entry is taken, 200
 * with THIS identity's own SCID is "you used to be here", anything else is
 * honestly unknown rather than a false "available". */
async function checkDomainAvailability(domain: string, ownScid: string): Promise<'available' | 'taken' | 'own-history' | 'unknown'> {
  if (!domain) return 'unknown'
  try {
    const resp = await fetch(`https://${domain}/.well-known/did.jsonl`, { method: 'GET' })
    if (resp.status === 404) return 'available'
    if (!resp.ok) return 'unknown'
    try {
      const firstLine = (await resp.text()).split('\n').map(l => l.trim()).find(Boolean)
      const scid = firstLine ? (JSON.parse(firstLine) as { parameters?: { scid?: string } }).parameters?.scid : undefined
      return scid === ownScid ? 'own-history' : 'taken'
    } catch {
      return 'taken'
    }
  } catch {
    return 'unknown'
  }
}

/** Ported from src.bak/ui/edit-identity.ts's openEditIdentityModal, narrowed
 * to domain only (see checkDomainAvailability's own note on why there is no
 * username field here) -- everything else (the confirm-before-submit
 * copy, the availability line, the domain-changed warning) is that file's
 * own markup and wording, verbatim. */
function openEditIdentityModal(did: string): void {
  if (!config?.onMoveIdentity) return
  let currentDomain: string, currentScid: string
  try {
    const parsed = parseWebvhDid(did)
    currentDomain = parsed.domain
    currentScid = parsed.scid
  } catch {
    return
  }

  const body = document.createElement('form')
  body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
  body.innerHTML = `
      <div style="font-size:12px;color:var(--text-dim)">
        Change this identity's domain. The identity's underlying key stays
        the same, so a contact who already knows you follows the change
        automatically the next time they resolve you.
      </div>
      <div data-role="domain-warning" style="font-size:12px;color:var(--text-dim)">
        Changing the domain moves this identity to a new destination. What
        that destination does with it from here on is entirely up to that
        destination, not biset — this only edits the bare identity document.
        Your mail address updates to match; existing mail history and your
        PGP key carry over unchanged.
      </div>
      <div style="display:flex;flex-direction:column;gap:3px">
        <label style="font-size:11px;color:var(--text-dim)">Domain</label>
        <input class="cmd-input" type="text" name="domain" required>
      </div>
      <div data-role="availability" style="font-size:12px;color:var(--text-dim);min-height:16px"></div>
      <div data-role="error" style="color:#ff3b30;font-size:12px;display:none"></div>
      <div data-role="ok" style="color:#34c759;font-size:12px;display:none"></div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px">
        <button type="button" data-role="cancel" class="cmd-page-btn" style="width:auto;padding:6px 14px">Cancel</button>
        <button type="submit" data-role="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 14px" disabled>Save</button>
      </div>`
  const dismiss = openModal('Edit identity', body)
  body.querySelector<HTMLButtonElement>('[data-role=cancel]')!.addEventListener('click', dismiss)

  const domainInput = body.elements.namedItem('domain') as HTMLInputElement
  domainInput.value = currentDomain

  const availEl = body.querySelector<HTMLElement>('[data-role=availability]')!
  const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
  let availToken = 0

  const setSubmitEnabled = (enabled: boolean): void => {
    submit.disabled = !enabled
    submit.style.opacity = enabled ? '1' : '0.4'
    submit.style.cursor = enabled ? 'pointer' : 'not-allowed'
  }
  setSubmitEnabled(false)

  const refresh = (): void => {
    const domain = domainInput.value.trim().toLowerCase()
    const unchanged = domain === currentDomain
    setSubmitEnabled(!unchanged && !!domain)
    if (unchanged || !domain) { availEl.textContent = ''; return }
    const token = ++availToken
    availEl.textContent = 'Checking availability…'
    checkDomainAvailability(domain, currentScid).then(status => {
      if (token !== availToken) return
      availEl.textContent = status === 'available' ? '✓ Available'
        : status === 'own-history' ? '↺ You used to be here — may or may not accept a move back, depending on the destination'
        : status === 'taken' ? '✗ Already in use at that location'
        : '? Could not check — the destination may not answer GET, or is unreachable'
      availEl.style.color = status === 'available' ? '#34c759' : status === 'own-history' ? '#ff9500' : status === 'taken' ? '#ff3b30' : 'var(--text-dim)'
    })
  }
  domainInput.addEventListener('input', refresh)

  body.addEventListener('submit', async ev => {
    ev.preventDefault()
    const domain = domainInput.value.trim().toLowerCase()
    const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
    const okEl = body.querySelector<HTMLElement>('[data-role=ok]')!
    errEl.style.display = 'none'; okEl.style.display = 'none'
    if (!domain) { errEl.textContent = 'Domain required'; errEl.style.display = 'block'; return }
    if (!confirm(`This will move this identity to ${domain}. It publishes a move entry to your current location and to the new one. It cannot be undone from here.`)) return

    setSubmitEnabled(false); submit.textContent = 'Saving…'
    try {
      const newDid = await config!.onMoveIdentity!(domain)
      okEl.textContent = `Saved — now ${newDid}`
      okEl.style.display = 'block'
      setTimeout(dismiss, 1200)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
    } finally {
      setSubmitEnabled(true); submit.textContent = 'Save'
    }
  })
}

/** A Spare/Sign Key phrase is its OWN independent 32-byte random seed, not
 * part of this identity's BIP39-master-seed hierarchy (unlike the Root Key,
 * identity/keys.ts's deriveRootKey) — so there is nothing to derive via
 * SLIP-10; the raw seed IS the ed25519 private key, same convention
 * ui/mnemonic.ts's promptForMnemonic echo already assumes. Using
 * deriveRootKey here would silently produce a DIFFERENT keypair than what
 * the echo shows, so the two must stay in lockstep. */
function spareKeyFromSeed(seed: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array } {
  return { privateKey: seed, publicKey: ed25519.getPublicKey(seed) }
}

// Verbatim from src.bak/ui/left-pane.ts's renderConfigPage() -- the WHOLE
// function's markup, not just the prerotation section (2026-08-26,
// corrected twice now: first for hand-rolling a replacement instead of
// using this at all, then for cherry-picking only the section this rewrite
// has a backend for. Per account-page.ts's own PAGE_HTML precedent --
// established, then apparently not generalized from -- an unwired element
// stays present looking exactly like the rest, it does not get deleted for
// having no backend yet). Notifications/Vault/+New Relay have no listeners
// attached below (no push-notification, markdown-vault, or multi-relay
// concept in this rewrite to wire them to) -- present, inert, same
// treatment as every other such element in this codebase.
//
// Three pieces of src.bak's OWN module state this template interpolated
// (vaultHandle/notifEnabled for the toggles' initial `on` class,
// currentIdentityDid() gating whether preRotationSection renders at all)
// don't exist here; substituted with their honest default (off / always
// rendered, since this rewrite's config page is only ever reachable once
// an identity exists at all). `'showDirectoryPicker' in window` is a real
// runtime capability check, not app state, and is kept exactly as-is.
const CONFIG_PAGE_HTML = `<div class="cmd-page-content wide-page">
      <div class="cmd-page-section">
        <h3>Notifications</h3>
        <div class="cmd-page-row">
          <span>Push notifications</span>
          <div class="toggle-switch" id="config-notif-toggle" style="cursor:pointer"></div>
        </div>
      </div>
      <div class="cmd-page-section">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
          <h3 style="margin:0">Key rotation</h3>
          <div class="toggle-switch" id="config-prerotation-toggle" style="cursor:pointer"></div>
        </div>
        <div style="display:flex;align-items:center;gap:10px;padding:6px 0">
          <button id="prerotation-rotate-btn" class="cmd-page-btn primary" style="display:none;padding:4px 12px;font-size:11px;font-weight:900;text-transform:uppercase;border-radius:20px;flex-shrink:0">Rotate</button>
          <span style="font-size:13px;color:var(--text-dim);flex-shrink:0">Sign Key:</span>
          <span id="config-prerotation-key" style="font-family:ui-monospace,monospace;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0;cursor:pointer" title="Click to show the Sign Key phrase"></span>
        </div>
        <div style="display:flex;align-items:center;gap:10px;padding:6px 0">
          <button id="prerotation-revoke-btn" class="cmd-page-btn primary" style="display:none;padding:4px 12px;font-size:11px;font-weight:900;text-transform:uppercase;border-radius:20px;flex-shrink:0">Revoke</button>
          <span style="font-size:13px;color:var(--text-dim);flex-shrink:0">Root Key:</span>
          <span id="config-rootkey" style="font-family:ui-monospace,monospace;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0;cursor:pointer" title="Click to show the Root Key phrase"></span>
        </div>
      </div>
      ${'showDirectoryPicker' in window ? `<div class="cmd-page-section">
        <h3>Vault (Markdown)</h3>
        <div class="cmd-page-row">
          <span>Vault</span>
          <div class="toggle-switch" id="config-vault-toggle" style="cursor:pointer"></div>
        </div>
      </div>` : ''}
      <button id="cmd-acc-fab" type="button"><span class="acc-new-account-plus">+</span>New Relay</button>
      <div id="cmd-acc-panel-backdrop"></div>
      <div class="cmd-page-section" id="cmd-acc-panel" style="display:none">
        <div class="cmd-acc-relay-row">
          <input id="cmd-acc-relay" class="cmd-input" type="text" placeholder="Relay URL (ex. biset.md)" required>
          <span id="cmd-acc-relay-badge"></span>
        </div>
        <div id="cmd-acc-relay-error" class="cmd-acc-error" style="display:none"></div>
        <div id="cmd-acc-choice">
          <button type="button" class="cmd-acc-choice-btn" data-mode="add">Sign up</button>
          <button type="button" class="cmd-acc-choice-btn" data-mode="login">Log in</button>
        </div>
        <div id="cmd-acc-signup-body" style="display:none"></div>
        <form id="cmd-acc-form" class="cmd-form" style="display:none" autocomplete="on">
          <div class="cmd-acc-email-row">
            <input id="cmd-acc-email" class="cmd-input" type="text" placeholder="Email" autocomplete="username" required>
          </div>
          <div class="cmd-acc-password-row">
            <input id="cmd-acc-password" class="cmd-input" type="password" placeholder="Password (plain JMAP account — leave blank for device-key login)" autocomplete="current-password">
          </div>
          <div class="cmd-acc-login-row">
            <button id="cmd-acc-add" type="submit" class="cmd-page-btn primary">Add</button>
          </div>
          <div id="cmd-acc-error" class="cmd-acc-error" style="display:none"></div>
        </form>
      </div>
    </div>`

/** Ported from src.bak/main.ts's own menu-page routing (`/config`, the
 * hamburger menu's own `.lp-hmenu-item[data-page="/config"]`,
 * ui/left-pane.ts's setupLeftPane) plus src.bak/ui/left-pane.ts's
 * onShowConfig -- the wiring half of CONFIG_PAGE_HTML's prerotation
 * section. Same "menu page" mechanics as showAccountPage (renders into
 * #active-thread, `data-menu-page` drives the CSS that hides the normal
 * thread view) -- this is a REAL config PAGE, reached from the hamburger
 * menu exactly where src.bak always had it, not a modal bolted onto the
 * identity dropdown (2026-08-26, corrected after doing exactly that
 * first). "Revoke" (src.bak's own button, always rendered but never wired
 * there either -- pre-rotation has no revoke operation, only activate/
 * rotate/deactivate, prerotation.ts's own three exports) stays present and
 * inert, same treatment as every other not-yet-wired element in this
 * codebase. */
export function showConfigPage(): void {
  const activeEl = document.getElementById('active-thread')
  const past = document.getElementById('past-threads')
  const app = document.getElementById('app')
  if (!activeEl || !config?.did) return
  configPageActive = true
  app?.setAttribute('data-menu-page', '/config')
  if (past) past.innerHTML = ''

  const headerTitle = document.getElementById('header-thread-title')
  if (headerTitle) { headerTitle.textContent = 'config'; headerTitle.className = '' }
  const groupIcon = document.getElementById('header-group-icon')
  if (groupIcon) groupIcon.style.display = 'none'
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = 'none'
  const dock = document.getElementById('reply-dock')
  if (dock) dock.innerHTML = ''

  const did = config.did
  const card = document.createElement('div')
  card.className = 'cmd-thread-card'
  card.id = 'focused-thread-card'
  card.innerHTML = CONFIG_PAGE_HTML
  activeEl.innerHTML = ''
  activeEl.appendChild(card)

  const preRotTog = card.querySelector<HTMLElement>('#config-prerotation-toggle')!
  const rotateBtn = card.querySelector<HTMLButtonElement>('#prerotation-rotate-btn')!
  const preRotKey = card.querySelector<HTMLElement>('#config-prerotation-key')!
  const rootKey = card.querySelector<HTMLElement>('#config-rootkey')!

  const refreshKeyLabel = async (): Promise<void> => {
    try {
      preRotKey.textContent = (await currentNextKeyHashes(did))[0] ?? ''
    } catch {
      preRotKey.textContent = ''
    }
  }
  rootKey.textContent = did

  const reflect = (active: boolean): void => {
    preRotTog.classList.toggle('on', active)
    rotateBtn.style.display = active ? '' : 'none'
  }

  const refresh = async (): Promise<void> => {
    try {
      reflect(await isPreRotationActive(did))
    } catch { /* leave the toggle as-is; a transient resolve failure isn't worth surfacing here */ }
    await refreshKeyLabel()
  }
  void refresh()

  preRotTog.addEventListener('click', async () => {
    const active = preRotTog.classList.contains('on')
    if (!active) {
      if (!config?.onActivateKeyRotation) return
      try {
        const seed = crypto.getRandomValues(new Uint8Array(32))
        const spare = spareKeyFromSeed(seed)
        const nextKeyHash = multikeyHashBase58(encodeMultikey(spare.publicKey))
        await showMnemonicOnce(seedToMnemonic(seed), {
          firstTime: true, title: 'Spare Key', badges: ['SPARE KEY'], fingerprint: encodeMultikey(spare.publicKey),
          subtitle: 'Write this down and keep it apart from your Root Key phrase. It is the only way to rotate or turn off key rotation later — losing it is as final as losing the Root Key.',
        })
        await config.onActivateKeyRotation(nextKeyHash)
        await refresh()
      } catch (e) {
        config?.showMessage?.(e instanceof Error ? e.message : String(e))
      }
      return
    }
    if (!config?.onDeactivateKeyRotation) return
    if (!confirm('Turn off key rotation and return full control to the Root Key?')) return
    try {
      const expectedHashes = await currentNextKeyHashes(did)
      const phrase = await promptForMnemonic({ title: 'Current Spare Key', badges: ['SPARE KEY'], expectedHashes, subtitle: 'Enter the current Spare Key phrase to deactivate key rotation.' })
      if (!phrase) return
      const revealed = spareKeyFromSeed(mnemonicToSeed(phrase))
      await config.onDeactivateKeyRotation(revealed.privateKey, revealed.publicKey)
      await refresh()
    } catch (e) {
      config?.showMessage?.(e instanceof Error ? e.message : String(e))
    }
  })

  rotateBtn.addEventListener('click', async () => {
    if (!config?.onRotateKeyRotation) return
    rotateBtn.disabled = true
    try {
      const expectedHashes = await currentNextKeyHashes(did)
      const phrase = await promptForMnemonic({ title: 'Current Spare Key', badges: ['SPARE KEY'], expectedHashes, subtitle: 'Enter the Spare Key phrase shown the last time key rotation was enabled or rotated.' })
      if (!phrase) return
      const revealed = spareKeyFromSeed(mnemonicToSeed(phrase))
      const nextSeed = crypto.getRandomValues(new Uint8Array(32))
      const nextSpare = spareKeyFromSeed(nextSeed)
      const nextKeyHash = multikeyHashBase58(encodeMultikey(nextSpare.publicKey))
      await showMnemonicOnce(seedToMnemonic(nextSeed), {
        firstTime: false, title: 'New Spare Key', badges: ['SPARE KEY'], fingerprint: encodeMultikey(nextSpare.publicKey),
        subtitle: 'Write this down. The previous Spare Key phrase no longer works.',
      })
      await config.onRotateKeyRotation(revealed.privateKey, revealed.publicKey, nextKeyHash)
      await refresh()
    } catch (e) {
      config?.showMessage?.(e instanceof Error ? e.message : String(e))
    } finally {
      rotateBtn.disabled = false
    }
  })

  // Sign Key reveal has no wiring to give it: biset never retains a copy of
  // a rotated-to Spare/Sign Key phrase once shown (prerotation.ts's own
  // header) -- that absence IS the design, not a gap. Root Key reveal is a
  // real capability (masterSeed is on disk); the click just needs it.
  preRotKey.addEventListener('click', () => config?.showMessage?.('The Sign Key phrase is never stored -- it was only ever shown once, when key rotation was last enabled or rotated'))
  rootKey.addEventListener('click', () => {
    if (!config?.masterSeed) return
    showMnemonic(fromHex(config.masterSeed), { firstTime: false })
  })
}

export function hideConfigPage(): void {
  if (!configPageActive) return
  configPageActive = false
  document.getElementById('app')?.removeAttribute('data-menu-page')
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = ''
  render()
}

/** Same item list src.bak's identity menu offered. "Log out" and "Edit
 * identity" are wired to real behavior -- the rest (passkey protection,
 * message export/import) have no corresponding backend in this rewrite yet,
 * same "present, inert" treatment as every other not-yet-wired element here
 * (this file's own header note). Restored 2026-08-25 after being dropped
 * entirely rather than ported inert -- per user direction, an unwired item
 * belongs in the menu looking exactly like the rest, not missing. */
function identityMenuItems(did: string): MenuItem[] {
  const noop = () => {}
  return [
    ...(config?.onConnectCoordinator ? [{ label: 'Connect coordinator', onClick: () => {
      void config?.onConnectCoordinator?.().then(() => config?.showMessage?.('Coordinator connected')).catch(error => config?.showMessage?.(error instanceof Error ? error.message : String(error)))
    } }] : []),
    ...(config?.onCreateCoordinatorInvitation ? [{ label: 'Invite coordinator device', onClick: () => {
      void config?.onCreateCoordinatorInvitation?.().then(async value => {
        try { await navigator.clipboard.writeText(value.invitation) } catch {}
        prompt(`Invitation expires ${new Date(value.expiresAt).toLocaleTimeString()}. Copy this code to the other device:`, value.invitation)
      }).catch(error => config?.showMessage?.(error instanceof Error ? error.message : String(error)))
    } }] : []),
    ...(config?.onApproveCoordinatorDevice ? [{ label: 'Approve coordinator device', onClick: () => {
      void config?.onApproveCoordinatorDevice?.().then(() => config?.showMessage?.('Coordinator device approved')).catch(error => config?.showMessage?.(error instanceof Error ? error.message : String(error)))
    } }] : []),
    ...(config?.onJoinCoordinatorInvitation ? [{ label: 'Join coordinator vault', onClick: () => {
      const invitation = prompt('Enter the coordinator invitation code:')?.trim()
      if (!invitation) return
      config?.showMessage?.('Waiting for approval on the existing device…')
      void config?.onJoinCoordinatorInvitation?.(invitation).then(() => config?.showMessage?.('Coordinator Vault joined')).catch(error => config?.showMessage?.(error instanceof Error ? error.message : String(error)))
    } }] : []),
    ...(config?.onResumeCoordinatorJoin ? [{ label: 'Resume coordinator join', onClick: () => {
      config?.showMessage?.('Waiting for approval on the existing device…')
      void config?.onResumeCoordinatorJoin?.().then(() => config?.showMessage?.('Coordinator Vault joined')).catch(error => config?.showMessage?.(error instanceof Error ? error.message : String(error)))
    } }] : []),
    { label: 'Protect with passkey', onClick: noop },
    { label: 'Export Messages', onClick: noop },
    { label: 'Import Messages', onClick: noop },
    ...(did.startsWith('did:webvh:') ? [
      { label: 'Edit identity', onClick: () => openEditIdentityModal(did) },
    ] : []),
    {
      label: 'Log out', danger: true, onClick: () => {
        if (!config?.onLogout) return
        if (!confirm('Log out and erase ALL local data (accounts, messages, keys)? This cannot be undone.')) return
        void config.onLogout()
      },
    },
  ]
}

// Verbatim from src.bak/ui/left-pane.ts's renderAccountPage() -- every
// element it had, including the ones this rewrite can't wire up yet
// (identity menu button, multi-account list, compose fab). Not trimmed:
// per user direction, an inert element stays present rather than being
// removed for looking unfinished.
const PAGE_HTML = `<div class="cmd-page-content wide-page">
  <div class="cmd-page-section" id="cmd-acc-identity-section">
    <div id="cmd-acc-identity-fields" title="Click to view devices and DID document">
      <div id="cmd-acc-identity-avatar" class="lp-avatar"></div>
      <div id="cmd-acc-identity-text">
        <div id="cmd-acc-identity-name-row">
          <span id="cmd-acc-identity-name"></span>
          <span id="cmd-acc-identity-name-edit" aria-hidden="true"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg></span>
        </div>
        <div id="cmd-acc-identity-did-row">
          <span id="cmd-acc-identity-did"></span>
          <button id="cmd-acc-identity-copy" type="button" aria-label="Copy DID" title="Copy DID"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg></button>
        </div>
      </div>
      <button id="cmd-acc-identity-menu-btn" type="button" aria-label="Menu"><svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg></button>
    </div>
    <div id="cmd-acc-sync-stalled" style="display:none"></div>
    <div id="cmd-acc-identity-expanded">
      <div class="acc-storage-header">
        <span class="acc-storage-title">Devices</span>
      </div>
      <div id="cmd-acc-identity-devices" class="acc-device-list"></div>
      <div class="acc-storage-header" style="margin-top:12px">
        <span class="acc-storage-title">DID:Webvh</span>
        <div class="acc-storage-actions">
          <button id="cmd-acc-identity-sync-btn" class="acc-storage-icon-btn" type="button" aria-label="Sync" title="Sync"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg></button>
        </div>
      </div>
      <pre id="cmd-acc-identity-doc"></pre>
    </div>
    <input id="cmd-acc-identity-devices-import-input" type="file" accept=".zip" style="display:none">
  </div>
  <div class="cmd-page-section" id="cmd-acc-list"></div>
  <button id="cmd-acc-compose-fab" class="compose-fab" type="button" aria-label="Compose" title="Compose"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg></button>
</div>`

export function showAccountPage(): void {
  const activeEl = document.getElementById('active-thread')
  const past = document.getElementById('past-threads')
  const app = document.getElementById('app')
  if (!activeEl || !config) return
  active = true
  app?.setAttribute('data-menu-page', '/account')
  if (past) past.innerHTML = ''

  // Park the signup form back in document.body BEFORE any repaint below --
  // if it's currently mounted inside the card this function is about to
  // wipe (activeEl.innerHTML = ''), that wipe would detach and lose the
  // live node (setupNewUserPage's listeners are bound to it by id, so it
  // must survive, not get recreated). Harmless no-op when it isn't mounted
  // here at all.
  unmountNewUserPageInline()

  const headerTitle = document.getElementById('header-thread-title')
  if (headerTitle) { headerTitle.textContent = 'account'; headerTitle.className = '' }
  const groupIcon = document.getElementById('header-group-icon')
  if (groupIcon) groupIcon.style.display = 'none'
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = 'none'
  // A reply box left over from whichever thread was open before navigating
  // here (thread.ts's own render() moves it into #reply-dock, position:fixed
  // -- nothing clears it just because a different page now occupies
  // #active-thread). Found live: the account page showed a stray reply box
  // floating at the bottom.
  const dock = document.getElementById('reply-dock')
  if (dock) dock.innerHTML = ''

  if (config.did === null) {
    // No local identity yet -- this state IS the account page in src.bak
    // too (main.ts's own `if (!sessions.length) showMenuPage('/account')`,
    // `#new`/`#restore` both just redirecting here): the signup form mounts
    // INLINE in place of the identity card, the same "the one thing there
    // is to do from this page anyway" the account-create.ts header
    // describes -- never a separate full-page overlay.
    const card = document.createElement('div')
    card.className = 'cmd-thread-card'
    card.id = 'focused-thread-card'
    activeEl.innerHTML = ''
    activeEl.appendChild(card)
    mountNewUserPageInline(card)
    setupNewUserPage()
    return
  }

  const did = config.did
  const label = parseWebvhDid(did).domain

  const card = document.createElement('div')
  card.className = 'cmd-thread-card'
  card.id = 'focused-thread-card'
  card.innerHTML = PAGE_HTML
  activeEl.innerHTML = ''
  activeEl.appendChild(card)

  const nameEl = document.getElementById('cmd-acc-identity-name')
  const didEl = document.getElementById('cmd-acc-identity-did')
  const avatarEl = document.getElementById('cmd-acc-identity-avatar')
  const docEl = document.getElementById('cmd-acc-identity-doc')
  const devicesEl = document.getElementById('cmd-acc-identity-devices')
  const section = document.getElementById('cmd-acc-identity-section')
  const fields = document.getElementById('cmd-acc-identity-fields')

  if (nameEl) nameEl.textContent = label
  // A self-asserted name (routing.json's `name`, set via the name/pencil
  // click below) overrides the bare domain label once it resolves -- fetched
  // in the background so the card still shows something immediately rather
  // than blocking render on a network round trip. Tracked separately from
  // the DOM (not re-read from nameEl.textContent) so the edit modal always
  // opens pre-filled with the real current value, even if the fetch is
  // still in flight when the user clicks.
  let currentName = label
  resolveWithRouting(did).then(doc => {
    if (doc?.name) {
      currentName = doc.name
      if (nameEl) nameEl.textContent = doc.name
    }
  }).catch(() => {})
  // Elided (SCID hidden) like src.bak's own account-page DID line
  // (ownDidParts/wireIdentityDid) -- this rewrite's did:webvh is always
  // subdomain-per-identity with no trailing username path segment
  // (create-genesis.ts), so the 46-char SCID is the only part worth
  // hiding; `did:webvh:{domain}` is the whole meaningful remainder. The
  // full DID stays in `title` (hover) and is what actually gets copied --
  // see the did-row click handler below, not this element's text.
  if (didEl) {
    didEl.textContent = shortWebvhDid(did)
    didEl.title = did
  }
  if (avatarEl) {
    avatarEl.setAttribute('style', avatarStyle(label))
    avatarEl.textContent = label.charAt(0).toUpperCase()
  }
  if (devicesEl) devicesEl.innerHTML = `<span class="acc-device-empty">Loading…</span>`
  // The device list has no read API of its own -- it's derived from the
  // resolved DID document's verificationMethod, the same one loadDoc below
  // already fetches for the JSON viewer (registerDeviceAndJoinSelfGroup,
  // identity/bootstrap.ts, appends one `#device-{hex}` entry per device
  // that's ever joined the self group; `#key-1` is the root key, not a
  // device, and routing.json's own keyAgreement/mlkem entries use `#k_`/
  // `#kk_` fragments -- neither matches). Found live, 2026-08-26: this said
  // "Device list not available yet" unconditionally even though the data
  // was already sitting right there in the same document this page already
  // resolves.
  resolveWithRouting(did).then(doc => {
    if (!devicesEl) return
    const deviceIds = (doc?.verificationMethod ?? [])
      .map(vm => vm.id)
      .filter(id => id.includes('#device-'))
    if (!deviceIds.length) { devicesEl.innerHTML = `<span class="acc-device-empty">${esc('No devices found')}</span>`; return }
    devicesEl.innerHTML = ''
    for (const id of deviceIds) {
      const fragment = id.slice(id.indexOf('#device-') + 1)
      const isThisDevice = id === config?.deviceKid
      const row = document.createElement('div')
      row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 0;font-size:13px'
      const label = document.createElement('span')
      label.style.cssText = 'font-family:ui-monospace,monospace;color:var(--text-dim)'
      label.textContent = fragment.length > 16 ? `#${fragment.slice(1, 9)}…` : `#${fragment}`
      label.title = id
      row.appendChild(label)
      if (isThisDevice) {
        const tag = document.createElement('span')
        tag.textContent = 'this device'
        tag.style.cssText = 'font-size:10px;font-weight:700;color:var(--accent);flex-shrink:0'
        row.appendChild(tag)
      } else if (config?.onRevokeDevice) {
        // Never offered for the current device's own row -- self-revoke
        // makes no sense (that's what logout already is, and
        // removeDeviceFromSelfGroup's own guard rejects it outright).
        const revokeBtn = document.createElement('button')
        revokeBtn.type = 'button'
        revokeBtn.textContent = 'Revoke'
        revokeBtn.style.cssText = 'font-size:11px;font-weight:700;color:#ff3b30;background:none;border:none;cursor:pointer;flex-shrink:0;padding:2px 4px'
        revokeBtn.addEventListener('click', async () => {
          if (!confirm(`Revoke this device? It will lose access to this identity's vault immediately and cannot be undone.`)) return
          revokeBtn.disabled = true
          revokeBtn.textContent = 'Revoking…'
          try {
            await config!.onRevokeDevice!(id)
            row.remove()
          } catch (e) {
            config?.showMessage?.('Revoke failed: ' + (e instanceof Error ? e.message : String(e)))
            revokeBtn.disabled = false
            revokeBtn.textContent = 'Revoke'
          }
        })
        row.appendChild(revokeBtn)
      }
      devicesEl.appendChild(row)
    }
  }).catch(() => {
    if (devicesEl) devicesEl.innerHTML = `<span class="acc-device-empty">${esc('Could not resolve devices')}</span>`
  })

  let docLoaded = false
  const loadDoc = async () => {
    if (!docEl) return
    docEl.textContent = 'Resolving…'
    try {
      const doc = await resolveWithRouting(did)
      docEl.textContent = doc ? JSON.stringify(doc, null, 2) : 'No document found (not yet published, or no gateway reachable)'
    } catch {
      docEl.textContent = 'Failed to resolve DID document'
    }
  }
  if (fields && section) {
    fields.addEventListener('click', () => {
      const wasExpanded = section.classList.contains('expanded')
      section.classList.toggle('expanded')
      if (!wasExpanded && !docLoaded) { docLoaded = true; void loadDoc() }
    })
  }
  document.getElementById('cmd-acc-identity-sync-btn')?.addEventListener('click', e => {
    e.stopPropagation()
    void loadDoc()
  })
  // The DID text + copy button are ONE click target, ONE listener on the
  // row (src.bak's wireIdentityDid exactly -- the button itself never had
  // its own handler there, it's inside the row and just rides its click).
  // A second, separate listener on the button (as this file had until
  // 2026-08-26) is not just redundant, it's wrong: stopPropagation on the
  // button's own listener means clicking the icon silently skips the row's
  // "DID copied" feedback the text click gets -- two different behaviors
  // for what's supposed to be one target.
  const didRow = document.getElementById('cmd-acc-identity-did-row')
  didRow?.addEventListener('click', e => {
    e.stopPropagation()
    navigator.clipboard?.writeText(did).then(() => config?.showMessage?.('DID copied')).catch(() => {})
  })
  // Name + pencil icon are the same "click to rename" target (src.bak's
  // `identityName.onclick` -- the pencil is a hover affordance, not a
  // separate control). Found live, 2026-08-26: neither was wired at all,
  // only the identity menu's own "Edit identity" item was -- so clicking
  // the pencil did nothing but toggle the card open/closed (bubbled to
  // `fields` below).
  const nameRow = document.getElementById('cmd-acc-identity-name-row')
  nameRow?.addEventListener('click', e => {
    e.stopPropagation()
    openDisplayNameModal(did, currentName)
  })
  const menuBtn = document.getElementById('cmd-acc-identity-menu-btn')
  menuBtn?.addEventListener('click', e => {
    e.stopPropagation()
    openDropdownMenu(menuBtn, identityMenuItems(did))
  })
  document.getElementById('cmd-acc-compose-fab')?.addEventListener('click', () => showComposePage())
}

export function hideAccountPage(): void {
  if (!active) return
  active = false
  document.getElementById('app')?.removeAttribute('data-menu-page')
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = ''
  // Same reasoning as showAccountPage()'s own call: park the signup form
  // back in document.body before render() repaints #active-thread out from
  // under it, in case the zero-identity state left it mounted here.
  unmountNewUserPageInline()
  render()
}
