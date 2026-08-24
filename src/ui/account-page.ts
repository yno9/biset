// Port of src.bak/ui/left-pane.ts's #account page. Per user direction
// (2026-08-24), this now uses the ORIGINAL renderAccountPage() HTML/CSS
// verbatim (avatar, name row, DID row + copy, the expandable
// devices/DID-document panel, the menu button) rather than a hand-shrunk
// substitute -- only the DATA behind it is cut down to what this rewrite's
// single-identity/single-local-vault model actually has:
//
//   - avatar/name/DID/copy: real, same as before.
//   - the expandable panel's DID document half is real too --
//     identity/webvh/resolver.ts's resolve() is the same resolution this
//     rewrite's own bootstrap already trusts, so "click to view devices and
//     DID document" now actually fetches and shows the live document.
//   - the devices list stays empty (no device-roster read API wired to the
//     UI yet -- that's a real gap, not a design choice, unlike the pieces
//     below).
//   - the identity menu button, multi-account list (#cmd-acc-list), and
//     compose fab (#cmd-acc-compose-fab) are hidden outright: display-name
//     editing/logout/republish/passkey-protect/claim-mail-account and
//     multi-relay accounts have no corresponding backend or concept here at
//     all, and a menu button that opens onto nothing is worse than no
//     button.
import { render } from './thread.ts'
import { esc, avatarStyle } from './format.ts'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { resolve } from '../identity/webvh/resolver.ts'

export interface AccountPageConfig {
  did: string
}

let config: AccountPageConfig | undefined
let active = false

export function configureAccountPage(next: AccountPageConfig): void {
  config = next
}

export function inAccountMode(): boolean {
  return active
}

const PAGE_HTML = `<div class="cmd-page-content wide-page">
  <div class="cmd-page-section" id="cmd-acc-identity-section">
    <div id="cmd-acc-identity-fields" title="Click to view DID document">
      <div id="cmd-acc-identity-avatar" class="lp-avatar"></div>
      <div id="cmd-acc-identity-text">
        <div id="cmd-acc-identity-name-row">
          <span id="cmd-acc-identity-name"></span>
        </div>
        <div id="cmd-acc-identity-did-row">
          <span id="cmd-acc-identity-did"></span>
          <button id="cmd-acc-identity-copy" type="button" aria-label="Copy DID" title="Copy DID"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg></button>
        </div>
      </div>
    </div>
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
  </div>
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

  const headerTitle = document.getElementById('header-thread-title')
  if (headerTitle) { headerTitle.textContent = 'account'; headerTitle.className = '' }
  const groupIcon = document.getElementById('header-group-icon')
  if (groupIcon) groupIcon.style.display = 'none'
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = 'none'
}

export function hideAccountPage(): void {
  if (!active) return
  active = false
  document.getElementById('app')?.removeAttribute('data-menu-page')
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = ''
  render()
}
