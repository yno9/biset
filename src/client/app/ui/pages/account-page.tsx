// The account page: the identity card (name, DID, capability expiry, and the DID document behind a
// click), then what hangs off it (the mediator, the key notice, PGP: account/account-list.tsx). With
// no identity yet, the one thing to do from here is sign up.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useStore } from '../../react/store.ts'
import { parseWebvhDid } from '../../../../protocol/webvh/identifier.ts'
import { resolve } from '../../../../protocol/webvh/resolver.ts'
import { AccountList, KeysPanel } from '../account/account-list.tsx'
import { cropAvatar } from '../account/avatar-crop.tsx'
import { chooseImage, PROFILE_CHANGED } from '../account/profile.ts'
import { DeltaChatIcon } from '../account/deltachat-icon.tsx'
import { copyInviteLink, joinDeltaChatInvite } from '../account/pgp-card.tsx'
import { openDropdownMenu, type MenuItem } from '../account/menu.tsx'
import { accountConfig, getAccountConfig } from '../account/state.ts'
import { avatarColor } from '../format.ts'
import { setPage } from '../state.ts'
import { NewUserPage } from './new-user-page.tsx'

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

/** Asks for the display name: a click on the name in the card, or the menu's "Set display name" while there is none. */
function changeDisplayName(current?: string): void {
  const profile = getAccountConfig()?.profile
  if (!profile) return
  const name = window.prompt('Display name (shown to the people you write to; empty removes it)', current ?? '')
  if (name === null) return
  void profile.setName(name.trim() || null).then(() => window.dispatchEvent(new Event(PROFILE_CHANGED))).catch(error => getAccountConfig()?.showMessage?.(errorText(error)))
}

type FileAction = MenuItem & { short: string }

/** Export, Import and Disconnect (Log out without a Wallet), the buttons of the Files tab (named `short`). */
function fileActions(): FileAction[] {
  const config = getAccountConfig()
  const wallet = config?.wallet
  const showMessage = (error: unknown) => config?.showMessage?.(errorText(error))
  const actions: FileAction[] = [
    { label: 'Export Messages', short: 'Export', onClick: () => { void config?.onExportMessages?.()?.catch(showMessage) } },
    { label: 'Import Messages', short: 'Import', onClick: () => { void config?.onImportMessages?.()?.catch(showMessage) } },
  ]
  if (wallet) {
    actions.push({
      label: 'Disconnect Wallet', short: 'Disconnect', danger: true, onClick: () => {
        const expires = new Date(wallet.capabilityExpiresAt).toLocaleDateString()
        if (!confirm(`Disconnect ${wallet.handle} from this browser? Its capability remains valid until ${expires}.`)) return
        void wallet.onDisconnect().catch(showMessage)
      },
    })
  } else {
    actions.push({
      label: 'Log out', short: 'Log out', danger: true, onClick: () => {
        if (!config?.onLogout) return
        if (!confirm('Log out and erase ALL local data (accounts, messages, keys)? This cannot be undone.')) return
        void config.onLogout()
      },
    })
  }
  return actions
}

/** The identity menu. A Wallet account can reconnect, move its messages, and disconnect; the rest of
 * the old menu (passkey protection) has no backend here. */
function identityMenuItems(currentName: string | undefined, did: { expanded: boolean; onToggle: () => void }): MenuItem[] {
  const config = getAccountConfig()
  const wallet = config?.wallet
  const showMessage = (error: unknown) => getAccountConfig()?.showMessage?.(errorText(error))
  const profile = config?.profile
  const didItem: MenuItem = { label: did.expanded ? 'Hide DID' : 'View DID', onClick: did.onToggle }
  const profileItems: MenuItem[] = profile ? [
    // Once there is a name, the name in the card is what changes it.
    ...(currentName ? [] : [{ label: 'Set display name', onClick: () => changeDisplayName() }]),
  ] : []
  if (wallet) {
    return [
      didItem,
      ...profileItems,
      ...(wallet.reconnectRequired && wallet.onReconnect ? [{ label: 'Reconnect Wallet', onClick: () => { void wallet.onReconnect?.().catch(showMessage) } }] : []),
    ]
  }
  return [
    didItem,
    ...profileItems,
    { label: 'Protect with passkey', onClick: () => {} },
  ]
}

/** The alias (the mail address, the DID's host): a click changes it, the pencil on its right says so. */
function AliasButton({ children }: { children: string }) {
  const wallet = useStore(accountConfig)?.wallet
  if (!wallet?.onChangeAlias) return <>{children}</>
  return (
    <span className="acc-alias-edit" role="button" tabIndex={0} data-tip="Change alias" style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 5 }}
      onClick={event => { event.stopPropagation(); void wallet.onChangeAlias?.().catch(error => { if (errorText(error) !== 'Cancelled.') getAccountConfig()?.showMessage?.(errorText(error)) }) }}
      onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); event.stopPropagation(); void wallet.onChangeAlias?.().catch(error => { if (errorText(error) !== 'Cancelled.') getAccountConfig()?.showMessage?.(errorText(error)) }) } }}>
      {children}
      <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true" style={{ opacity: .6, flex: 'none' }}><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z" /></svg>
    </span>
  )
}

/** The first character, upper-cased, of a display name or of the mail address (a character, not a UTF-16 unit). */
const initialOf = (text: string): string => (Array.from(text)[0] ?? '').toUpperCase()

/** `did:webvh:` + SCID + `:alias.did.md` on one line: when the card is narrow the SCID gives way (ellipsis), the
 * alias never does. */
function DidText({ did }: { did: string }) {
  const parts = did.split(':')
  if (parts.length < 4) return <span className="acc-did-scid">{did}</span>
  return (
    <>
      <span className="acc-did-fixed">{parts.slice(0, 2).join(':')}:</span>
      <span className="acc-did-scid">{parts[2]}</span>
      <span className="acc-did-fixed">:{parts.slice(3).join(':')}</span>
    </>
  )
}

function IdentityCard({ did }: { did: string }) {
  const label = parseWebvhDid(did).domain
  const accountState = useStore(accountConfig)
  const wallet = accountState?.wallet
  const [name, setName] = useState(label)
  const [own, setOwn] = useState<{ name?: string; avatar?: string }>({})
  const [expanded, setExpanded] = useState(false)
  const [doc, setDoc] = useState('')
  const docLoaded = useRef(false)
  const menuButton = useRef<HTMLButtonElement>(null)

  // The card is a view of the signed did:webvh document: a self-asserted name overrides the bare
  // domain label once it resolves, in the background so the card shows something at once.
  useEffect(() => {
    let current = true
    resolve(did).then(found => { if (current && found?.name) setName(found.name) }).catch(() => {})
    return () => { current = false }
  }, [did])

  // The identity's own name and picture, from its card; looked at again when the menu changes them.
  const profile = accountState?.profile
  useEffect(() => {
    if (!profile) return
    let current = true
    const load = () => { void profile.current().then(found => { if (current) setOwn(found) }).catch(() => {}) }
    load()
    window.addEventListener(PROFILE_CHANGED, load)
    return () => { current = false; window.removeEventListener(PROFILE_CHANGED, load) }
  }, [profile])

  const loadDoc = async () => {
    setDoc('Resolving…')
    try {
      const found = await resolve(did)
      setDoc(found ? JSON.stringify(found, null, 2) : 'No document found (not yet published, or no gateway reachable)')
    } catch { setDoc('Failed to resolve DID document') }
  }

  const toggleDid = () => { setExpanded(open => !open); if (!expanded && !docLoaded.current) { docLoaded.current = true; void loadDoc() } }

  return (
    <div className={`cmd-page-section${expanded ? ' expanded' : ''}`} id="cmd-acc-identity-section">
      <div id="cmd-acc-identity-fields">
        <div id="cmd-acc-identity-avatar" className="lp-avatar" role={profile ? 'button' : undefined} data-tip={profile ? (own.avatar ? 'Change profile picture' : 'Set profile picture') : undefined}
          style={{ background: avatarColor(label), ...(profile ? { cursor: 'pointer' } : {}) }}
          // The picture is set where it is shown: a click on it asks for an image (not the card opening).
          onClick={profile ? event => {
            event.stopPropagation()
            void chooseImage().then(file => file && cropAvatar(file)).then(avatar => { if (avatar) return profile.setAvatar(avatar) }).then(() => window.dispatchEvent(new Event(PROFILE_CHANGED))).catch(error => { if (errorText(error) !== 'Cancelled.') getAccountConfig()?.showMessage?.(errorText(error)) })
          } : undefined}>{own.avatar ? <img className="lp-avatar-img" src={own.avatar} alt="" /> : initialOf(own.name?.trim() || label)}</div>
        <div id="cmd-acc-identity-text">
          <div id="cmd-acc-identity-name-row"><span id="cmd-acc-identity-name">{own.name ? <><span className="acc-display-name" role={profile ? 'button' : undefined} data-tip={profile ? 'Change display name' : undefined}
            onClick={profile ? event => { event.stopPropagation(); changeDisplayName(own.name) } : undefined}>{own.name}</span><span className="acc-name-sep">|</span></> : null}<AliasButton>{name.replace(/\.did\.md$/, '@did.md')}</AliasButton></span></div>
          {/* Clicking the DID text copies it. */}
          <div id="cmd-acc-identity-did-row"
            onClick={event => { event.stopPropagation(); navigator.clipboard?.writeText(did).then(() => getAccountConfig()?.showMessage?.('DID copied')).catch(() => {}) }}>
            <span id="cmd-acc-identity-did" data-tip={did}><DidText did={did} /></span>
            <svg id="cmd-acc-identity-copy-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>
          </div>
        </div>
        <button ref={menuButton} id="cmd-acc-identity-menu-btn" type="button" aria-label="Menu"
          onClick={event => { event.stopPropagation(); openDropdownMenu(menuButton.current!, identityMenuItems(own.name, { expanded, onToggle: toggleDid })) }}>
          <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5" /><circle cx="12" cy="12" r="1.5" /><circle cx="12" cy="19" r="1.5" /></svg>
        </button>
      </div>
      <div id="cmd-acc-identity-expanded">
        <div className="acc-storage-header">
          <span className="acc-storage-title">DID:Webvh</span>
          <div className="acc-storage-actions">
            <button id="cmd-acc-identity-sync-btn" className="acc-storage-icon-btn" type="button" aria-label="Sync" data-tip="Sync" onClick={event => { event.stopPropagation(); void loadDoc() }}>
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>
            </button>
          </div>
        </div>
        <pre id="cmd-acc-identity-doc">{doc}</pre>
      </div>
    </div>
  )
}

function FilesPanel() {
  useStore(accountConfig)
  return (
    <div id="cmd-acc-files">
      {fileActions().map(action => (
        <button key={action.short} type="button" className={action.danger ? 'acc-file-btn danger' : 'acc-file-btn'} onClick={action.onClick}>{action.short}</button>
      ))}
    </div>
  )
}

/** Delta Chat, at the foot of the page: join someone's invite, or copy this identity's own invite link. */
function DeltaChatBar() {
  const config = useStore(accountConfig)
  const pgp = config?.pgp
  if (!pgp) return null
  const showMessage = (text: string) => config?.showMessage?.(text)
  return (
    <div id="cmd-acc-deltachat">
      <DeltaChatIcon />
      <button type="button" onClick={() => joinDeltaChatInvite(pgp, showMessage)}>Join</button>
      <span aria-hidden="true">|</span>
      <button type="button" onClick={() => copyInviteLink(pgp, showMessage)}>Copy URL</button>
    </div>
  )
}

const TABS = ['Services', 'Keys', 'Files'] as const
type Tab = typeof TABS[number]

/** The bar under the identity card, and the panel it picks. Services is what the page showed so far (the
 * mediator), Keys has the devices and the PGP key, Files has Export / Import / Disconnect. */
function AccountTabs() {
  const [tab, setTab] = useState<Tab>('Services')
  const [bar, setBar] = useState<{ left: number; width: number }>()
  const tabs = useRef<Partial<Record<Tab, HTMLButtonElement | null>>>({})
  // The underline is one element that slides (CSS transition on left and width) to the chosen tab; it
  // first appears already in place, so nothing slides on load.
  useLayoutEffect(() => {
    const measure = () => { const button = tabs.current[tab]; if (button) setBar({ left: button.offsetLeft, width: button.offsetWidth }) }
    measure()
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [tab])
  return (
    <>
      <nav id="cmd-acc-nav" role="tablist" aria-label="Account">
        {TABS.map(name => (
          <button key={name} ref={element => { tabs.current[name] = element }} type="button" role="tab" className="acc-nav-tab" aria-selected={tab === name}
            // The pointer over a tab picks it; a click (touch, keyboard) does too.
            onPointerEnter={event => { if (event.pointerType === 'mouse') setTab(name) }} onClick={() => setTab(name)}>{name}</button>
        ))}
        {bar ? <span className="acc-nav-underline" style={{ left: bar.left, width: bar.width }} /> : null}
      </nav>
      <div className="cmd-page-section" id="cmd-acc-list" role="tabpanel">
        {tab === 'Services' ? <AccountList /> : tab === 'Keys' ? <KeysPanel /> : <FilesPanel />}
      </div>
    </>
  )
}

export function AccountPage() {
  const config = useStore(accountConfig)
  if (!config) return null
  // No local identity yet: the account page is the landing page for that state, and its one job is
  // the sign-up form, in place of the identity card.
  if (config.did === null) {
    return <div id="active-thread"><div className="cmd-thread-card" id="focused-thread-card"><NewUserPage /></div></div>
  }
  return (
    <div id="active-thread">
      <div className="cmd-thread-card" id="focused-thread-card">
        <div className="cmd-page-content wide-page">
          <IdentityCard did={config.did} />
          <AccountTabs />
          <DeltaChatBar />
          <button id="cmd-acc-compose-fab" className="compose-fab" type="button" aria-label="Compose" data-tip="Compose" onClick={() => setPage('compose')}>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z" /></svg>
          </button>
        </div>
      </div>
    </div>
  )
}
