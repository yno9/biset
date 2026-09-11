import { render } from '../thread.ts'
import { getAccountConfig } from './state.ts'

let configPageActive = false

export function inConfigMode(): boolean {
  return configPageActive
}

// This page contains only Biset-owned configuration. DID controller key
// material and pre-rotation belong to the did.md Wallet that owns the Master
// mnemonic, so they must not be represented here as inert Biset controls.
const CONFIG_PAGE_HTML = `<div class="cmd-page-content wide-page">
      <div class="cmd-page-section">
        <h3>Notifications</h3>
        <div class="cmd-page-row">
          <span>Push notifications</span>
          <div class="toggle-switch" id="config-notif-toggle" style="cursor:pointer"></div>
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

/** Renders Biset configuration into the command-page surface. */
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

  const card = document.createElement('div')
  card.className = 'cmd-thread-card'
  card.id = 'focused-thread-card'
  card.innerHTML = CONFIG_PAGE_HTML
  activeEl.innerHTML = ''
  activeEl.appendChild(card)
}

export function hideConfigPage(): void {
  if (!configPageActive) return
  configPageActive = false
  document.getElementById('app')?.removeAttribute('data-menu-page')
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = ''
  render()
}
