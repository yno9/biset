// Minimal port of src.bak/ui/left-pane.ts's #account page (renderAccountPage
// + the identity-section half of renderAccountsList/loadIdentityDevices),
// cut down to what this rewrite's single-identity/single-local-vault model
// can actually show: the identity's own DID, copy-to-clipboard, and nothing
// else. Left out (all present in the pre-rewrite version, none ported):
// multi-account list (cmd-acc-list -- multi-relay concept this rewrite
// doesn't have), device list/DID-document viewer/sync button (no device
// roster read API wired to the UI yet), display-name editing, logout,
// republish, claim-mail-account, passkey protection -- every one of those
// needs either a backend endpoint this rewrite doesn't expose to the UI yet
// or a concept (multi-relay, mail claim) it doesn't have at all.
import { render } from './thread.ts'
import { esc } from './format.ts'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'

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

export function showAccountPage(): void {
  const activeEl = document.getElementById('active-thread')
  const past = document.getElementById('past-threads')
  const app = document.getElementById('app')
  if (!activeEl) return
  active = true
  app?.setAttribute('data-menu-page', '/account')
  if (past) past.innerHTML = ''

  const did = config?.did ?? ''
  const label = config ? parseWebvhDid(config.did).domain : ''
  activeEl.innerHTML = `
    <div class="cmd-thread-card" id="focused-thread-card">
      <div class="cmd-page-content wide-page">
        <div class="cmd-page-section" id="cmd-acc-identity-section">
          <div id="cmd-acc-identity-fields">
            <div id="cmd-acc-identity-text">
              <div id="cmd-acc-identity-name-row">
                <span id="cmd-acc-identity-name">${esc(label)}</span>
              </div>
              <div id="cmd-acc-identity-did-row">
                <span id="cmd-acc-identity-did">${esc(did)}</span>
                <button id="cmd-acc-identity-copy" type="button" aria-label="Copy DID" title="Copy DID">
                  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `
  document.getElementById('cmd-acc-identity-copy')?.addEventListener('click', () => {
    if (did) navigator.clipboard?.writeText(did).catch(() => {})
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
