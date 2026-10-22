// The account page: the identity card (name, DID, capability expiry, and the DID document behind a
// click), then what hangs off it (the mediator, the key notice, PGP: account/account-list.tsx). With
// no identity yet, the one thing to do from here is sign up.
import { useEffect, useRef, useState } from 'react'
import { useStore } from '../../react/store.ts'
import { parseWebvhDid } from '../../../../protocol/webvh/identifier.ts'
import { resolve } from '../../../../protocol/webvh/resolver.ts'
import { AccountList } from '../account/account-list.tsx'
import { cropAvatar } from '../account/avatar-crop.tsx'
import { chooseImage, PROFILE_CHANGED } from '../account/profile.ts'
import { copyInviteLink, joinDeltaChatInvite, PgpKeyRow } from '../account/pgp-card.tsx'
import { openDropdownMenu, type MenuItem } from '../account/menu.tsx'
import { accountConfig, getAccountConfig } from '../account/state.ts'
import { avatarColor } from '../format.ts'
import { setPage } from '../state.ts'
import { NewUserPage } from './new-user-page.tsx'

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

/** The identity menu. A Wallet account can reconnect, move its messages, and disconnect; the rest of
 * the old menu (passkey protection) has no backend here. */
function identityMenuItems(): MenuItem[] {
  const config = getAccountConfig()
  const wallet = config?.wallet
  const showMessage = (error: unknown) => getAccountConfig()?.showMessage?.(errorText(error))
  const pgp = config?.pgp
  const profile = config?.profile
  const profileItems: MenuItem[] = profile ? [
    { label: 'Remove profile picture', onClick: () => { void profile.setAvatar(null).then(() => window.dispatchEvent(new Event(PROFILE_CHANGED))).catch(showMessage) } },
    { label: 'Set display name', onClick: () => {
      const name = window.prompt('Display name (shown to the people you write to; empty removes it)')
      if (name === null) return
      void profile.setName(name.trim() || null).then(() => window.dispatchEvent(new Event(PROFILE_CHANGED))).catch(showMessage)
    } },
  ] : []
  const invite: MenuItem[] = pgp ? [
    { label: 'Copy Delta Chat invite', onClick: () => copyInviteLink(pgp, text => config?.showMessage?.(text)) },
    { label: 'Join a Delta Chat invite', onClick: () => joinDeltaChatInvite(pgp, text => config?.showMessage?.(text)) },
  ] : []
  if (wallet) {
    return [
      ...profileItems,
      ...invite,
      ...(wallet.reconnectRequired && wallet.onReconnect ? [{ label: 'Reconnect Wallet', onClick: () => { void wallet.onReconnect?.().catch(showMessage) } }] : []),
      { label: 'Export Messages', onClick: () => { void getAccountConfig()?.onExportMessages?.().catch(showMessage) } },
      { label: 'Import Messages', onClick: () => { void getAccountConfig()?.onImportMessages?.().catch(showMessage) } },
      {
        label: 'Disconnect Wallet', danger: true, onClick: () => {
          const expires = new Date(wallet.capabilityExpiresAt).toLocaleDateString()
          if (!confirm(`Disconnect ${wallet.handle} from this browser? Its capability remains valid until ${expires}.`)) return
          void wallet.onDisconnect().catch(showMessage)
        },
      },
    ]
  }
  return [
    ...profileItems,
    ...invite,
    { label: 'Protect with passkey', onClick: () => {} },
    { label: 'Export Messages', onClick: () => { void getAccountConfig()?.onExportMessages?.() } },
    { label: 'Import Messages', onClick: () => { void getAccountConfig()?.onImportMessages?.() } },
    {
      label: 'Log out', danger: true, onClick: () => {
        const current = getAccountConfig()
        if (!current?.onLogout) return
        if (!confirm('Log out and erase ALL local data (accounts, messages, keys)? This cannot be undone.')) return
        void current.onLogout()
      },
    },
  ]
}

/** The alias (the mail address, the DID's host): a click changes it, the pencil on its right says so. */
function AliasButton({ children }: { children: string }) {
  const wallet = useStore(accountConfig)?.wallet
  if (!wallet?.onChangeAlias) return <>{children}</>
  return (
    <span className="acc-alias-edit" role="button" tabIndex={0} title="Change alias" style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 5 }}
      onClick={event => { event.stopPropagation(); void wallet.onChangeAlias?.().catch(error => { if (errorText(error) !== 'Cancelled.') getAccountConfig()?.showMessage?.(errorText(error)) }) }}
      onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); event.stopPropagation(); void wallet.onChangeAlias?.().catch(error => { if (errorText(error) !== 'Cancelled.') getAccountConfig()?.showMessage?.(errorText(error)) }) } }}>
      {children}
      <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true" style={{ opacity: .6, flex: 'none' }}><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z" /></svg>
    </span>
  )
}

function IdentityCard({ did }: { did: string }) {
  const label = parseWebvhDid(did).domain
  const accountState = useStore(accountConfig)
  const wallet = accountState?.wallet
  const pgp = accountState?.pgp
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

  return (
    <div className={`cmd-page-section${expanded ? ' expanded' : ''}`} id="cmd-acc-identity-section">
      <div id="cmd-acc-identity-fields" title="Click to view DID document"
        onClick={() => { setExpanded(open => !open); if (!expanded && !docLoaded.current) { docLoaded.current = true; void loadDoc() } }}>
        <div id="cmd-acc-identity-avatar" className="lp-avatar" role={profile ? 'button' : undefined} title={profile ? 'Set profile picture' : undefined}
          style={{ background: avatarColor(label), ...(profile ? { cursor: 'pointer' } : {}) }}
          // The picture is set where it is shown: a click on it asks for an image (not the card opening).
          onClick={profile ? event => {
            event.stopPropagation()
            void chooseImage().then(file => file && cropAvatar(file)).then(avatar => { if (avatar) return profile.setAvatar(avatar) }).then(() => window.dispatchEvent(new Event(PROFILE_CHANGED))).catch(error => { if (errorText(error) !== 'Cancelled.') getAccountConfig()?.showMessage?.(errorText(error)) })
          } : undefined}>{own.avatar ? <img className="lp-avatar-img" src={own.avatar} alt="" /> : label.charAt(0).toUpperCase()}</div>
        <div id="cmd-acc-identity-text">
          <div id="cmd-acc-identity-name-row"><span id="cmd-acc-identity-name">{own.name ?? <AliasButton>{name.replace(/\.did\.md$/, '@did.md')}</AliasButton>}</span></div>
          {/* Clicking the DID text copies it. */}
          <div id="cmd-acc-identity-did-row"
            onClick={event => { event.stopPropagation(); navigator.clipboard?.writeText(did).then(() => getAccountConfig()?.showMessage?.('DID copied')).catch(() => {}) }}>
            <svg id="cmd-acc-webvh-icon" viewBox="290 90 700 850" width="13" height="13" fill="currentColor" stroke="currentColor" aria-hidden="true">
              <path fill="none" strokeWidth="54" d="M580 150 L928 351 V735 M578 150 V541 L698 610 M578 255 L815 392 V810 M578 347 L698 416 V875 M348 285 V650 L700 853 M462 213 V594 L698 718" />
              <circle cx="580" cy="150" r="48" /><circle cx="928" cy="735" r="48" /><circle cx="816" cy="810" r="48" /><circle cx="702" cy="875" r="48" /><circle cx="351" cy="285" r="48" /><circle cx="463" cy="213" r="48" />
            </svg>
            <span id="cmd-acc-identity-did" title={did}>{own.name ? <>{did.split(':').slice(0, 3).join(':')}:<AliasButton>{did.split(':').slice(3).join(':')}</AliasButton></> : did}</span>
          </div>
          {pgp ? <PgpKeyRow config={pgp} showMessage={text => getAccountConfig()?.showMessage?.(text)} /> : null}
        </div>
        <button ref={menuButton} id="cmd-acc-identity-menu-btn" type="button" aria-label="Menu"
          onClick={event => { event.stopPropagation(); openDropdownMenu(menuButton.current!, identityMenuItems()) }}>
          <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5" /><circle cx="12" cy="12" r="1.5" /><circle cx="12" cy="19" r="1.5" /></svg>
        </button>
      </div>
      <div id="cmd-acc-identity-expanded">
        <div className="acc-storage-header">
          <span className="acc-storage-title">DID:Webvh</span>
          <div className="acc-storage-actions">
            <button id="cmd-acc-identity-sync-btn" className="acc-storage-icon-btn" type="button" aria-label="Sync" title="Sync" onClick={event => { event.stopPropagation(); void loadDoc() }}>
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>
            </button>
          </div>
        </div>
        <pre id="cmd-acc-identity-doc">{doc}</pre>
      </div>
    </div>
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
          <div className="cmd-page-section" id="cmd-acc-list"><AccountList /></div>
          <button id="cmd-acc-compose-fab" className="compose-fab" type="button" aria-label="Compose" title="Compose" onClick={() => setPage('compose')}>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z" /></svg>
          </button>
        </div>
      </div>
    </div>
  )
}
