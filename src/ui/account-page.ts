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
//     UI yet), and the identity menu button/#cmd-acc-list/compose fab have
//     no click handler (display-name editing/logout/republish/multi-relay
//     accounts/new-message compose have no corresponding backend or
//     concept here at all yet) -- present in the DOM, inert for now, same
//     as every other not-yet-wired element left-pane.ts's own header notes.
import { render } from './thread.ts'
import { esc, avatarStyle } from './format.ts'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { resolve } from '../identity/webvh/resolver.ts'

export interface AccountPageConfig {
  did: string
  /** This device's DIDComm keyAgreement kid (identity/bootstrap.ts's
   * enableDidComm), or undefined if this identity hasn't opted in yet.
   * Undefined also while coreBaseUrl/apexDomain aren't configured -- same
   * gate the mail send path uses -- since enabling DIDComm without a core
   * to publish routing.json against has nothing to do. */
  didCommKid?: string
  onEnableDidComm?(): Promise<void>
}

let config: AccountPageConfig | undefined
let active = false

export function configureAccountPage(next: AccountPageConfig): void {
  config = next
}

export function inAccountMode(): boolean {
  return active
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
      <!-- New section (2026-08-25), not part of src.bak: that build's DIDComm
           was mediator/queue-based, a different design with no equivalent UI
           to port. Styled to match the DID:Webvh section above it. -->
      <div class="acc-storage-header" style="margin-top:12px">
        <span class="acc-storage-title">DIDComm</span>
      </div>
      <div id="cmd-acc-didcomm-status"></div>
    </div>
    <input id="cmd-acc-identity-devices-import-input" type="file" accept=".zip" style="display:none">
  </div>
  <div class="cmd-page-section" id="cmd-acc-list"></div>
  <button id="cmd-acc-compose-fab" class="compose-fab" type="button" aria-label="Compose" title="Compose"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg></button>
</div>`

function renderDidCommStatus(): void {
  const el = document.getElementById('cmd-acc-didcomm-status')
  if (!el || !config) return
  if (config.didCommKid) {
    el.innerHTML = `<span class="acc-device-empty">${esc(`Enabled — ${config.didCommKid}`)}</span>`
    return
  }
  if (!config.onEnableDidComm) {
    el.innerHTML = `<span class="acc-device-empty">${esc('Not available (core not configured)')}</span>`
    return
  }
  el.innerHTML = `<button id="cmd-acc-didcomm-enable-btn" class="acc-storage-icon-btn" type="button">${esc('Enable DIDComm')}</button>`
  document.getElementById('cmd-acc-didcomm-enable-btn')?.addEventListener('click', async e => {
    e.stopPropagation()
    const btn = e.currentTarget as HTMLButtonElement
    btn.disabled = true
    btn.textContent = 'Enabling…'
    try {
      await config!.onEnableDidComm!()
      renderDidCommStatus()
    } catch (error) {
      btn.disabled = false
      btn.textContent = 'Enable DIDComm'
      const errorEl = document.createElement('div')
      errorEl.className = 'acc-device-empty'
      errorEl.textContent = `Failed: ${error instanceof Error ? error.message : String(error)}`
      el.appendChild(errorEl)
    }
  })
}

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
  renderDidCommStatus()

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
