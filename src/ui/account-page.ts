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
import { avatarStyle } from './format.ts'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { resolve } from '../identity/webvh/resolver.ts'
import { shortWebvhDid } from './did-display.ts'
import { showComposePage } from './compose-page.ts'
import { mountNewUserPageInline, unmountNewUserPageInline, setupNewUserPage } from './account-create.ts'
import { getAccountConfig, type VaultCardState, type VaultCardStatus } from './account/state.ts'
import { openDropdownMenu, type MenuItem } from './account/menu.ts'
import { openDisplayNameModal, openEditIdentityModal } from './account/identity-modals.ts'

// The page's own state and markup live here; the pieces below were split out
// (2026-09-05) into ./account/ by concern -- config state + the config types
// (state.ts), the dropdown menu (menu.ts), the generic modal (modal.ts), the
// display-name/edit-identity modals (identity-modals.ts) and the /config
// menu page (config-page.ts). They stay re-exported from here so main.ts and
// ui/left-pane.ts keep importing the account page's API from one module.
export { configureAccountPage } from './account/state.ts'
// VaultCardStatus only: main.ts holds one to pass to updateVaultCardStatus.
// AccountPageConfig is configureAccountPage's parameter type and has no
// caller outside account/, so it stays internal (S7's rule).
export type { VaultCardStatus } from './account/state.ts'
export { showConfigPage, hideConfigPage, inConfigMode } from './account/config-page.ts'

let active = false

/** Update only the Vault card when the background MIMI Vault session moves
 * between checking/connected/error states. Repainting the whole account page
 * here would close an open identity menu or expanded Vault panel every ten
 * seconds, so this intentionally targets the one reusable relay-card slot. */
export function updateVaultCardStatus(status: VaultCardStatus): void {
  const config = getAccountConfig()
  if (!config?.did) return
  config.vault = status
  // renderVaultCard owns (and replaces) the shared account-card list. Keep
  // the adjacent Wallet session card in that list on lightweight Vault
  // status updates; otherwise every 10-second sync makes it disappear until
  // the next full account-page render.
  if (active) {
    renderVaultCard()
    renderWalletAccountCard()
  }
}

export function inAccountMode(): boolean {
  return active
}

/** Same item list src.bak's identity menu offered. "Log out" and "Edit
 * identity" are wired to real behavior -- the rest (passkey protection,
 * message export/import) have no corresponding backend in this rewrite yet,
 * same "present, inert" treatment as every other not-yet-wired element here
 * (this file's own header note). Restored 2026-08-25 after being dropped
 * entirely rather than ported inert -- per user direction, an unwired item
 * belongs in the menu looking exactly like the rest, not missing. */
function identityMenuItems(did: string): MenuItem[] {
  if (getAccountConfig()?.wallet) {
    return [{
      label: 'Disconnect Wallet', danger: true, onClick: () => {
        const config = getAccountConfig()
        if (!confirm(`Disconnect ${config!.wallet!.handle} from this browser? The capability can still be revoked from did.md Wallet.`)) return
        void config!.wallet!.onDisconnect().catch(error => getAccountConfig()?.showMessage?.(error instanceof Error ? error.message : String(error)))
      },
    }]
  }
  const noop = () => {}
  return [
    { label: 'Protect with passkey', onClick: noop },
    { label: 'Export Messages', onClick: noop },
    { label: 'Import Messages', onClick: noop },
    ...(did.startsWith('did:webvh:') ? [
      { label: 'Edit identity', onClick: () => openEditIdentityModal(did) },
    ] : []),
    {
      label: 'Log out', danger: true, onClick: () => {
        const config = getAccountConfig()
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
    <div id="cmd-acc-identity-fields" title="Click to view DID document">
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

function coordinatorHost(url: string): string {
  try { return new URL(url).host } catch { return url }
}

function shortenedOpaqueId(value: string): string {
  return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value
}

/** The old relay card's visual grammar, now used for the one persistence
 * service this client actually has: dot + service/address heading, compact
 * stats, and a click-to-expand storage panel. */
function renderVaultCard(): void {
  const list = document.getElementById('cmd-acc-list')
  const status = getAccountConfig()?.vault
  if (!list || !status) return
  const wasExpanded = document.getElementById('cmd-acc-vault-card')?.classList.contains('expanded') ?? false
  list.replaceChildren()

  const colors: Record<VaultCardState, string> = {
    checking: '#8e8e93', connecting: '#ff9500', syncing: '#0a84ff',
    connected: '#34c759', 'reconnect-required': '#ff9500', error: '#ff3b30',
  }
  const labels: Record<VaultCardState, string> = {
    checking: 'Checking connection…', connecting: 'Connecting…', syncing: 'Syncing…',
    connected: 'Connected', 'reconnect-required': 'Reconnect required', error: 'Connection error',
  }

  const wrap = document.createElement('div')
  wrap.className = 'acc-card-wrap'
  if (wasExpanded) wrap.classList.add('expanded')
  wrap.id = 'cmd-acc-vault-card'
  const row = document.createElement('div')
  row.className = 'cmd-page-row'
  row.style.cssText = 'gap:12px;align-items:center;padding:10px 12px'
  const left = document.createElement('div')
  left.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:4px'
  const head = document.createElement('div')
  head.style.cssText = 'display:flex;align-items:center;gap:8px;min-width:0'
  const dot = document.createElement('span')
  dot.style.cssText = `width:8px;height:8px;border-radius:50%;flex-shrink:0;background:${colors[status.state]}`
  const title = document.createElement('span')
  title.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:0.04em;color:var(--accent2, #888);flex-shrink:0'
  title.textContent = 'Vault'
  const sep = document.createElement('span')
  sep.style.cssText = 'color:var(--text-dim);flex-shrink:0'
  sep.textContent = ':'
  const endpoint = document.createElement('span')
  endpoint.style.cssText = 'font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'
  endpoint.textContent = coordinatorHost(status.coordinatorUrl)
  head.append(dot, title, sep, endpoint)

  const stats = document.createElement('div')
  stats.style.cssText = 'display:flex;flex-wrap:wrap;gap:12px;font-size:11px;color:var(--text-dim)'
  const state = document.createElement('span')
  state.textContent = labels[status.state]
  state.style.color = status.state === 'error' ? '#ff3b30' : status.state === 'reconnect-required' ? '#ff9500' : ''
  stats.appendChild(state)
  if (status.latestSeq !== undefined) {
    const sync = document.createElement('span')
    sync.textContent = `Sync: ${status.localSeq ?? '…'}/${status.latestSeq}`
    stats.appendChild(sync)
  }
  if (status.checkpointSeq !== undefined) {
    const checkpoint = document.createElement('span')
    checkpoint.textContent = `Checkpoint: ${status.checkpointSeq}`
    stats.appendChild(checkpoint)
  }
  left.append(head, stats)
  row.appendChild(left)

  // A reconnect-required/error state used to offer a "Reconnect" button here
  // (Coordinator's OIDC re-auth). MIMI has no equivalent user action --
  // membership plus the MLS leaf signature authenticate every request, so
  // recovering from either state is automatic on the next sync poll rather
  // than something a click drives.

  const panel = document.createElement('div')
  panel.className = 'acc-storage-panel'
  const panelHeader = document.createElement('div')
  panelHeader.className = 'acc-storage-header'
  const panelTitle = document.createElement('span')
  panelTitle.className = 'acc-storage-title'
  panelTitle.textContent = 'Details'
  panelHeader.appendChild(panelTitle)
  const details = document.createElement('div')
  details.className = 'acc-storage-tree'
  details.style.cssText = 'display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 12px;color:var(--text-dim)'
  const addDetail = (name: string, value: string | undefined, titleText?: string) => {
    if (value === undefined) return
    const key = document.createElement('span')
    key.textContent = name
    const val = document.createElement('span')
    val.style.cssText = 'font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text)'
    val.textContent = value
    if (titleText) val.title = titleText
    details.append(key, val)
  }
  addDetail('Endpoint', status.coordinatorUrl)
  addDetail('Vault ID', status.vaultId ? shortenedOpaqueId(status.vaultId) : '—', status.vaultId)
  addDetail('Stream', status.latestSeq === undefined ? '—' : `${status.localSeq ?? '…'} / ${status.latestSeq}`)
  addDetail('Checkpoint', status.checkpointSeq ?? '—')
  if (status.detail) addDetail('Status', status.detail)
  panel.append(panelHeader, details)
  if (status.devices?.length) {
    const devicesHeader = document.createElement('div')
    devicesHeader.className = 'acc-storage-header'
    devicesHeader.style.marginTop = '14px'
    const devicesTitle = document.createElement('span')
    devicesTitle.className = 'acc-storage-title'
    devicesTitle.textContent = 'Devices'
    devicesHeader.appendChild(devicesTitle)
    const devices = document.createElement('div')
    devices.className = 'acc-device-list'
    for (const device of status.devices) {
      const line = document.createElement('div')
      line.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 0;font-size:13px'
      const id = document.createElement('span')
      id.style.cssText = 'font-family:ui-monospace,monospace;color:var(--text-dim)'
      const fragment = device.deviceId.includes('#') ? device.deviceId.slice(device.deviceId.indexOf('#')) : device.deviceId
      id.textContent = fragment.length > 18 ? `${fragment.slice(0, 10)}…` : fragment
      id.title = device.deviceId
      line.appendChild(id)
      if (device.current) {
        const tag = document.createElement('span')
        tag.textContent = 'this device'
        tag.style.cssText = 'font-size:10px;font-weight:700;color:var(--accent);flex-shrink:0'
        line.appendChild(tag)
      } else if (getAccountConfig()?.onRemoveVaultDevice) {
        const remove = document.createElement('button')
        remove.type = 'button'
        remove.className = 'cmd-page-btn'
        remove.style.cssText = 'padding:2px 8px;font-size:10px;font-weight:700;flex-shrink:0;color:#ff3b30'
        remove.textContent = 'Remove'
        remove.addEventListener('click', event => {
          event.stopPropagation()
          if (!confirm(`Remove this device (${device.deviceId}) from the Vault? It will stop syncing immediately.`)) return
          remove.disabled = true
          remove.textContent = '…'
          void getAccountConfig()?.onRemoveVaultDevice?.(device.deviceId)
            .then(() => getAccountConfig()?.showMessage?.('Device removed'))
            .catch(error => {
              getAccountConfig()?.showMessage?.(error instanceof Error ? error.message : String(error))
              remove.disabled = false
              remove.textContent = 'Remove'
            })
        })
        line.appendChild(remove)
      }
      devices.appendChild(line)
    }
    panel.append(devicesHeader, devices)
  }
  wrap.append(row, panel)
  row.addEventListener('click', () => wrap.classList.toggle('expanded'))
  list.appendChild(wrap)
}

function renderWalletAccountCard(): void {
  const wallet = getAccountConfig()?.wallet
  const list = document.getElementById('cmd-acc-list')
  if (!wallet || !list) return
  const row = document.createElement('div')
  row.className = 'cmd-page-row'
  row.style.cssText = 'gap:12px;align-items:center;padding:10px 12px'
  const detail = document.createElement('div')
  detail.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:4px'
  const title = document.createElement('div')
  title.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600'
  const dot = document.createElement('span')
  dot.style.cssText = 'width:8px;height:8px;border-radius:50%;background:#34c759;flex-shrink:0'
  const label = document.createElement('span')
  label.textContent = 'did.md Wallet'
  title.append(dot, label)
  const description = document.createElement('div')
  description.style.cssText = 'font-size:11px;color:var(--text-dim)'
  description.textContent = wallet.deviceKid
    ? `Connected · MLS device enrolled · capability until ${new Date(wallet.capabilityExpiresAt).toLocaleDateString()}`
    : `Connected · reconnect to enroll this browser's MLS device · capability until ${new Date(wallet.capabilityExpiresAt).toLocaleDateString()}`
  detail.append(title, description)
  const messaging = document.createElement('div')
  messaging.style.cssText = 'font-size:11px;color:var(--text-dim)'
  if (wallet.didComm) {
    messaging.textContent = wallet.didComm.error
      ? `DIDComm endpoint needs attention: ${wallet.didComm.error}`
      : `DIDComm endpoint registered · ${wallet.didComm.mediatorUrl}`
  } else if (wallet.onEnableMessaging) {
    const enable = document.createElement('button')
    enable.type = 'button'
    enable.className = 'cmd-page-btn'
    enable.style.cssText = 'width:auto;padding:3px 7px;font-size:10px;margin-top:2px'
    enable.textContent = 'Enable DIDComm messaging'
    enable.addEventListener('click', () => {
      enable.disabled = true
      void wallet.onEnableMessaging!().catch(error => {
        getAccountConfig()?.showMessage?.(error instanceof Error ? error.message : String(error))
        enable.disabled = false
      })
    })
    messaging.append(enable)
  } else {
    messaging.textContent = 'DIDComm messaging is not configured for this Biset deployment'
  }
  detail.append(messaging)
  const disconnect = document.createElement('button')
  disconnect.type = 'button'
  disconnect.className = 'cmd-page-btn'
  disconnect.style.cssText = 'width:auto;padding:5px 9px;font-size:11px'
  disconnect.textContent = 'Disconnect'
  disconnect.addEventListener('click', () => {
    if (!confirm(`Disconnect ${wallet.handle} from this browser? The capability can still be revoked from did.md Wallet.`)) return
    disconnect.disabled = true
    void wallet.onDisconnect().catch(error => {
      getAccountConfig()?.showMessage?.(error instanceof Error ? error.message : String(error))
      disconnect.disabled = false
    })
  })
  row.append(detail, disconnect)
  list.appendChild(row)
}

export function showAccountPage(): void {
  const activeEl = document.getElementById('active-thread')
  const past = document.getElementById('past-threads')
  const app = document.getElementById('app')
  const config = getAccountConfig()
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
  renderVaultCard()
  renderWalletAccountCard()

  const nameEl = document.getElementById('cmd-acc-identity-name')
  const didEl = document.getElementById('cmd-acc-identity-did')
  const avatarEl = document.getElementById('cmd-acc-identity-avatar')
  const docEl = document.getElementById('cmd-acc-identity-doc')
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
  // The identity card is a view of the signed did:webvh document.  It must
  // not depend on Biset's optional routing.json: a freshly created did.md
  // identity has no DIDComm device/routing file yet, while its did.jsonl is
  // already a complete, independently verifiable DID document.
  resolve(did).then(doc => {
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
    navigator.clipboard?.writeText(did).then(() => getAccountConfig()?.showMessage?.('DID copied')).catch(() => {})
  })
  // Name + pencil icon are the same "click to rename" target (src.bak's
  // `identityName.onclick` -- the pencil is a hover affordance, not a
  // separate control). Found live, 2026-08-26: neither was wired at all,
  // only the identity menu's own "Edit identity" item was -- so clicking
  // the pencil did nothing but toggle the card open/closed (bubbled to
  // `fields` below).
  const nameRow = document.getElementById('cmd-acc-identity-name-row')
  if (config.onEditName) nameRow?.addEventListener('click', e => {
    e.stopPropagation()
    openDisplayNameModal(did, currentName)
  })
  if (config.wallet) {
    document.getElementById('cmd-acc-identity-name-edit')?.setAttribute('style', 'display:none')
  }
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
