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
//     UI yet), and #cmd-acc-list/compose fab have no click handler
//     (multi-relay accounts/new-message compose have no corresponding
//     backend or concept here at all yet) -- present in the DOM, inert for
//     now, same as every other not-yet-wired element left-pane.ts's own
//     header notes. The identity menu button IS wired (identityMenuItems
//     below) -- Log out is real, the rest of that menu's items stay inert
//     the same way.
import { render } from './thread.ts'
import { esc, avatarStyle } from './format.ts'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { resolve } from '../identity/webvh/resolver.ts'

export interface AccountPageConfig {
  did: string
  /** Confirmed and invoked by the identity menu's "Log out" item
   * (src.bak/ui/left-pane.ts's confirmAndLogout -- confirm() stays here in
   * the UI layer, this is just the "actually do it" half). */
  onLogout?(): Promise<void>
}

let config: AccountPageConfig | undefined
let active = false

export function configureAccountPage(next: AccountPageConfig): void {
  config = next
}

export function inAccountMode(): boolean {
  return active
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

/** Same item list src.bak's identity menu offered. Only "Log out" is wired
 * to real behavior -- the rest (passkey protection, message export/import,
 * edit identity) have no corresponding backend in this rewrite yet, same
 * "present, inert" treatment as every other not-yet-wired element here
 * (this file's own header note). Restored 2026-08-25 after being dropped
 * entirely rather than ported inert -- per user direction, an unwired item
 * belongs in the menu looking exactly like the rest, not missing. */
function identityMenuItems(did: string): MenuItem[] {
  const noop = () => {}
  return [
    { label: 'Protect with passkey', onClick: noop },
    { label: 'Export Messages', onClick: noop },
    { label: 'Import Messages', onClick: noop },
    ...(did.startsWith('did:webvh:') ? [{ label: 'Edit identity', onClick: noop }] : []),
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
  if (didEl) didEl.textContent = did
  if (avatarEl) {
    avatarEl.setAttribute('style', avatarStyle(label))
    avatarEl.textContent = label.charAt(0).toUpperCase()
  }
  if (devicesEl) devicesEl.innerHTML = `<span class="acc-device-empty">${esc('Device list not available yet')}</span>`

  let docLoaded = false
  const loadDoc = async () => {
    if (!docEl) return
    docEl.textContent = 'Resolving…'
    try {
      const doc = await resolve(did)
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
  document.getElementById('cmd-acc-identity-copy')?.addEventListener('click', e => {
    e.stopPropagation()
    navigator.clipboard?.writeText(did).catch(() => {})
  })
  const menuBtn = document.getElementById('cmd-acc-identity-menu-btn')
  menuBtn?.addEventListener('click', e => {
    e.stopPropagation()
    openDropdownMenu(menuBtn, identityMenuItems(did))
  })

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
}

export function hideAccountPage(): void {
  if (!active) return
  active = false
  document.getElementById('app')?.removeAttribute('data-menu-page')
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = ''
  render()
}
