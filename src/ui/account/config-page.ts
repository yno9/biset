import { render } from '../thread.ts'
import { currentNextKeyHashes } from '../../identity/webvh/prerotation.ts'
import { showMnemonic } from '../mnemonic.ts'
import { fromHex } from '../../identity/bootstrap.ts'
import { getAccountConfig } from './state.ts'

let configPageActive = false

export function inConfigMode(): boolean {
  return configPageActive
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
          <span style="font-size:12px;font-weight:800;color:var(--accent)">Always active</span>
        </div>
        <div style="display:flex;align-items:center;gap:10px;padding:6px 0">
          <button id="prerotation-rotate-btn" class="cmd-page-btn primary" style="padding:4px 12px;font-size:11px;font-weight:900;text-transform:uppercase;border-radius:20px;flex-shrink:0">Rotate</button>
          <span style="font-size:13px;color:var(--text-dim);flex-shrink:0">Next Spare commitment:</span>
          <span id="config-prerotation-key" style="font-family:ui-monospace,monospace;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0"></span>
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
  const config = getAccountConfig()
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

  const preRotKey = card.querySelector<HTMLElement>('#config-prerotation-key')!
  const rootKey = card.querySelector<HTMLElement>('#config-rootkey')!

  rootKey.textContent = did

  const refresh = async (): Promise<void> => {
    try {
      const hashes = await currentNextKeyHashes(did)
      if (hashes.length !== 1) throw new Error('identity does not satisfy permanent pre-rotation invariants')
      preRotKey.textContent = hashes[0]!
    } catch (e) { preRotKey.textContent = e instanceof Error ? e.message : String(e) }
  }
  void refresh()

  // #prerotation-rotate-btn is intentionally left with no click wiring here:
  // Spare Key rotation used to commit through the Coordinator self-group,
  // which has been retired outright and has no MIMI-native replacement yet
  // (key-rotation work is deferred). Present in the DOM, inert for now --
  // same treatment this file's own header already gives every other
  // not-yet-wired element (the devices list, #cmd-acc-list, and so on).

  // Sign Key reveal has no wiring to give it: biset never retains a copy of
  // a rotated-to Spare/Sign Key phrase once shown (prerotation.ts's own
  // header) -- that absence IS the design, not a gap. Root Key reveal is a
  // real capability (masterSeed is on disk); the click just needs it.
  rootKey.addEventListener('click', () => {
    const masterSeed = getAccountConfig()?.masterSeed
    if (!masterSeed) return
    showMnemonic(fromHex(masterSeed), { firstTime: false })
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
