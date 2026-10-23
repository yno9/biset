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
import { ConfigPanel } from './config-page.tsx'
import { randomDisplayName } from '../account/default-name.ts'
import { useOwnProfile } from '../account/use-own-profile.ts'
import { requestDisplayName } from '../account/display-name-dialog.tsx'
import { DeltaChatIcon } from '../account/deltachat-icon.tsx'
import { OnionIcon } from '../account/onion-icon.tsx'
import { readBisetConfig } from '../config.ts'
import { copyInviteLink, joinDeltaChatInvite } from '../account/pgp-card.tsx'
import { accountConfig, getAccountConfig } from '../account/state.ts'
import { avatarColor } from '../format.ts'
import { GeneratedAvatar } from '../generated-avatar.tsx'
import { setPage } from '../state.ts'
import { NewUserPage } from './new-user-page.tsx'

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

/** Asks for the display name: a click on the name in the card, or the menu's "Set display name" while there is none. */
function changeDisplayName(): void {
  const profile = getAccountConfig()?.profile
  if (!profile) return
  void requestDisplayName().then(name => {
    if (name === null) return
    return profile.setName(name.trim() || randomDisplayName()).then(() => window.dispatchEvent(new Event(PROFILE_CHANGED)))
  }).catch(error => getAccountConfig()?.showMessage?.(errorText(error)))
}

type FileAction = { label: string; short: string; danger?: boolean; onClick: () => void }

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

function IdentityCard({ did }: { did: string }) {
  const label = parseWebvhDid(did).domain
  const accountState = useStore(accountConfig)
  const [name, setName] = useState(label)

  // The card is a view of the signed did:webvh document: a self-asserted name overrides the bare
  // domain label once it resolves, in the background so the card shows something at once.
  useEffect(() => {
    let current = true
    resolve(did).then(found => { if (current && found?.name) setName(found.name) }).catch(() => {})
    return () => { current = false }
  }, [did])

  // The identity's own name and picture, from its card; looked at again when they change.
  const profile = accountState?.profile
  const own = useOwnProfile(profile)

  return (
    <div className="cmd-page-section" id="cmd-acc-identity-section">
      <div id="cmd-acc-identity-fields">
        <div id="cmd-acc-identity-avatar" className="lp-avatar" role={profile ? 'button' : undefined} data-tip={profile ? (own.avatar ? 'Change profile picture' : 'Set profile picture') : undefined}
          style={{ background: avatarColor(own.name?.trim() || label), ...(profile ? { cursor: 'pointer' } : {}) }}
          // The picture is set where it is shown: a click on it asks for an image (not the card opening).
          onClick={profile ? event => {
            event.stopPropagation()
            void chooseImage().then(file => file && cropAvatar(file)).then(avatar => { if (avatar) return profile.setAvatar(avatar) }).then(() => window.dispatchEvent(new Event(PROFILE_CHANGED))).catch(error => { if (errorText(error) !== 'Cancelled.') getAccountConfig()?.showMessage?.(errorText(error)) })
          } : undefined}>{own.avatar ? <img className="lp-avatar-img" src={own.avatar} alt="" /> : <GeneratedAvatar name={own.name?.trim() || label} />}</div>
        <div id="cmd-acc-identity-text">
          {/* Two lines: the display name, and under it the alias (the mail address). Without a name the alias is the one line, and takes the name's look. */}
          {own.name ? (
            <div id="cmd-acc-identity-name-row"><span id="cmd-acc-identity-name"><span className="acc-display-name" role={profile ? 'button' : undefined} data-tip={profile ? 'Change display name' : undefined}
              onClick={profile ? event => { event.stopPropagation(); changeDisplayName() } : undefined}>{own.name}</span></span></div>
          ) : null}
          <div id="cmd-acc-identity-alias-row"><span className={own.name ? 'acc-identity-alias' : 'acc-identity-alias as-name'}><AliasButton>{name.replace(/\.did\.md$/, '@did.md')}</AliasButton></span>
            {profile && !own.name ? <button type="button" className="acc-name-add" onClick={event => { event.stopPropagation(); changeDisplayName() }}>Set display name</button> : null}
          </div>
        </div>
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
      <button type="button" onClick={() => copyInviteLink(pgp, showMessage)}>Invite</button>
    </div>
  )
}

/** Under the Delta Chat row, when this app is also served over Tor: the onion address to copy (the page's own, by the deployment's config). */
function OnionBar() {
  const onion = readBisetConfig().appOnionUrl
  if (!onion) return null
  return (
    <div id="cmd-acc-onion">
      <OnionIcon size={16} />
      <button type="button" onClick={() => { navigator.clipboard?.writeText(onion).then(() => getAccountConfig()?.showMessage?.('Onion URL copied')).catch(() => {}) }}>Onion URL</button>
    </div>
  )
}

const TABS = ['Services', 'Keys', 'Files', 'Config'] as const
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
        {tab === 'Services' ? <AccountList /> : tab === 'Keys' ? <KeysPanel /> : tab === 'Files' ? <FilesPanel /> : <ConfigPanel />}
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
          <OnionBar />
          <button id="cmd-acc-compose-fab" className="compose-fab" type="button" aria-label="Compose" data-tip="Compose" onClick={() => setPage('compose')}>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z" /></svg>
          </button>
        </div>
      </div>
    </div>
  )
}
