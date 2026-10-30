// The account page: the identity card (name, DID, capability expiry, and the DID document behind a
// click), then what hangs off it (the mediator, the key notice, PGP: account/account-list.tsx). With
// no identity yet, the one thing to do from here is sign up.
import { addressOfHost } from '../did-display.ts'
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { createStore, useStore } from '../../react/store.ts'
import { IslandTabs, useIslandWheel, type ThreadNav } from '../island.tsx'
import { hamburgerTrigger } from '../hamburger-menu.tsx'
import { resolveDidDocument } from '../../../../protocol/did-resolve.ts'
import { AccountList, KeysPanel } from '../account/account-list.tsx'
import { cropAvatar } from '../account/avatar-crop.tsx'
import { chooseImage, PROFILE_CHANGED } from '../account/profile.ts'
import { ConfigPanel } from './config-page.tsx'
import { randomDisplayName } from '../account/default-name.ts'
import { useOwnProfile } from '../account/use-own-profile.ts'
import { requestDisplayName } from '../account/display-name-dialog.tsx'
import { DeltaChatIcon } from '../account/deltachat-icon.tsx'
import { OnionIcon } from '../account/onion-icon.tsx'
import { GitHubIcon } from '../account/github-icon.tsx'
import { APP_VERSION, applyUpdate, updateWaiting } from '../update.ts'
import { readBisetConfig } from '../config.ts'
import { copyInviteLink, joinDeltaChatInvite } from '../account/pgp-card.tsx'
import { accountConfig, getAccountConfig } from '../account/state.ts'
import { avatarColor } from '../format.ts'
import { GeneratedAvatar } from '../generated-avatar.tsx'
import { NewUserPage } from './new-user-page.tsx'
import { scrollToFocused } from '../scroll.ts'
import { Messages } from '../thread-page.tsx'
import { useThreads } from '../use-threads.ts'

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

/** Export, Import and Disconnect (Log out without a Wallet), the buttons at the head of the Data tab (named `short`). */
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

/** The account is a conversation with yourself, and its threads are these four: the island's chevrons (and a scroll over it) move
 * between them, as between the threads of an inbox. */
const TABS = ['Notepad', 'Services', 'Data', 'Config'] as const
type Tab = typeof TABS[number]
export const accountTab = createStore<Tab>('Notepad')

/** The account's other threads, in the strip above the open one (pulled open like an inbox's other threads). */
export function AccountPast() {
  const tab = useStore(accountTab)
  return (
    <>
      {TABS.filter(name => name !== tab).map(name => (
        <div key={name} className="past-row">
          <div className="past-row-header" onClick={() => accountTab.set(name)}>
            <span className="past-row-title">{name}</span>
          </div>
        </div>
      ))}
    </>
  )
}

/** The island of the account: who you are (a click on the picture, the name or the alias changes it), and the open thread's title. */
export function AccountIsland() {
  const accountState = useStore(accountConfig)
  const did = accountState?.did
  const tab = useStore(accountTab)
  // The address the identity is published at; the DID itself names none.
  const label = accountState?.wallet?.handle ?? did ?? ''
  const [name, setName] = useState(label)
  // The identity is a view of the signed did:vh document: a self-asserted name overrides the bare domain label once it resolves.
  useEffect(() => {
    if (!did) return
    let current = true
    resolveDidDocument(did).then(found => { if (current && found?.name) setName(found.name) }).catch(() => {})
    return () => { current = false }
  }, [did])
  const profile = accountState?.profile
  const own = useOwnProfile(profile)
  const fields = useRef<HTMLDivElement>(null)
  const position = TABS.indexOf(tab)
  const nav: ThreadNav = { position, count: TABS.length, go: step => { const next = TABS[position + step]; if (next) accountTab.set(next) } }
  useIslandWheel(fields, nav)
  if (!did) return null
  const alias = addressOfHost(name)
  const shown = own.name?.trim() || alias
  return (
    <div id="conv-meta" className="conv-line2-low">
      <div id="conv-fields" ref={fields}>
        <div id="conv-to">
          <div id="conv-avatar" className="lp-avatar" role={profile ? 'button' : undefined} data-tip={profile ? (own.avatar ? 'Change profile picture' : 'Set profile picture') : undefined}
            style={{ background: avatarColor(alias.toLowerCase()), ...(profile ? { cursor: 'pointer' } : {}) }}
            // The picture is set where it is shown: a click on it asks for an image.
            onClick={profile ? () => {
              void chooseImage().then(file => file && cropAvatar(file)).then(avatar => { if (avatar) return profile.setAvatar(avatar) }).then(() => window.dispatchEvent(new Event(PROFILE_CHANGED))).catch(error => { if (errorText(error) !== 'Cancelled.') getAccountConfig()?.showMessage?.(errorText(error)) })
            } : undefined}>{own.avatar ? <img className="lp-avatar-img" src={own.avatar} alt="" /> : <GeneratedAvatar name={alias.toLowerCase()} />}</div>
          <div id="conv-text">
            <div id="conv-line1">
              <span id="conv-name" role={profile && own.name ? 'button' : undefined} data-tip={profile && own.name ? 'Change display name' : undefined}
                style={profile && own.name ? { cursor: 'pointer' } : undefined} onClick={profile && own.name ? changeDisplayName : undefined}>{shown}</span>
              {own.name ? <span id="conv-address"><AliasButton>{alias}</AliasButton></span>
                : profile ? <button type="button" className="acc-name-add" onClick={changeDisplayName}>Set display name</button> : null}
            </div>
            <div id="conv-line2"><IslandTabs tabs={TABS} current={tab} onPick={name => accountTab.set(name)} /></div>
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

type FootContext = 'delta' | 'version' | 'onion'
const SOURCE_URL = 'https://github.com/yno9/biset'

/** The foot of the page: three icons in a row (Delta Chat, the source and its version, and, when this app is also served over Tor, its onion
 * address). Over an icon, its menu opens over the command box, in place of the field; a click anywhere else (the margins of the box included)
 * puts it away. Without a mouse, a tap on the icon opens it. */
export function AccountFoot() {
  const config = useStore(accountConfig)
  const pgp = config?.pgp
  const onion = readBisetConfig().appOnionUrl
  const waiting = useStore(updateWaiting)
  const [context, setContext] = useState<FootContext | null>(null)
  useEffect(() => {
    if (!context) return
    const away = (event: PointerEvent): void => { if (!(event.target as Element | null)?.closest?.('[data-foot-item]')) setContext(null) }
    document.addEventListener('pointerdown', away, true)
    return () => document.removeEventListener('pointerdown', away, true)
  }, [context])
  const showMessage = (text: string) => config?.showMessage?.(text)
  const done = (action: () => void) => () => { setContext(null); action() }
  // What each action does: the icon itself does it where there is only one (the source, the onion address); Delta Chat has two, so its icon only opens the menu.
  const copyOnion = (): void => { if (onion) navigator.clipboard?.writeText(onion).then(() => showMessage('Onion URL copied')).catch(() => {}) }
  const openSource = (): void => { if (waiting) applyUpdate(); else window.open(SOURCE_URL, '_blank', 'noopener,noreferrer') }
  const icon = (id: FootContext, label: string, children: ReactNode, action?: () => void) => (
    <button type="button" className={`foot-icon${context === id ? ' open' : ''}`} data-foot-item aria-label={label} title={label}
      onPointerEnter={event => { if (event.pointerType === 'mouse') setContext(id) }}
      onClick={() => { if (action) { setContext(null); action() } else setContext(id) }}>{children}</button>
  )
  return (
    <div id="cmd-acc-foot">
      {pgp ? icon('delta', 'Delta Chat', <DeltaChatIcon />) : null}
      {icon('version', waiting ? 'Update available' : `Version ${APP_VERSION}`, <><GitHubIcon />{waiting ? <i className="update-dot" /> : null}</>, openSource)}
      {onion ? icon('onion', 'Onion URL', <OnionIcon size={16} />, copyOnion) : null}
      {context ? (
        <div className="foot-menu" role="menu">
          {context === 'delta' && pgp ? (
            <>
              <button type="button" data-foot-item onClick={done(() => joinDeltaChatInvite(pgp, showMessage))}>Join an invite</button>
              <span aria-hidden="true">|</span>
              <button type="button" data-foot-item onClick={done(() => copyInviteLink(pgp, showMessage))}>Copy my invite</button>
            </>
          ) : null}
          {context === 'version' ? (
            <>
              {waiting ? <button type="button" className="update-available" data-foot-item onClick={done(applyUpdate)}>Update available</button> : null}
              <a href={SOURCE_URL} target="_blank" rel="noreferrer" data-foot-item onClick={() => setContext(null)}>GitHub · v{APP_VERSION}</a>
            </>
          ) : null}
          {context === 'onion' && onion ? (
            <button type="button" data-foot-item onClick={done(copyOnion)}>Copy onion URL</button>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

/** The Data thread: the files' three buttons in one row, then the keys (what were the Files and the Keys threads). */
function DataPanel() {
  return <><FilesPanel /><KeysPanel /></>
}

/** The Notepad: what you wrote to yourself, as the messages of a conversation. */
function NotepadPanel() {
  const { notepad } = useThreads()
  const count = notepad.messages.length
  // Open at the end, as a conversation does.
  useLayoutEffect(() => { scrollToFocused() }, [count])
  // The same page as an open conversation (ui/thread-page.tsx), so that it is spaced as one.
  return <div id="active-thread"><div className="thread-card focused-card" id="focused-thread-card"><Messages group={notepad} /></div></div>
}

/** The page of the open thread (a tab of the account): Notepad, Services, Data or Config. */
export function AccountPage() {
  const config = useStore(accountConfig)
  const tab = useStore(accountTab)
  if (!config) return null
  // No local identity yet: the account page is the landing page for that state, and its one job is
  // the sign-up form.
  if (config.did === null) {
    return <div id="active-thread"><div className="cmd-thread-card" id="focused-thread-card"><NewUserPage /></div></div>
  }
  if (tab === 'Notepad') return <NotepadPanel />
  return (
    <div id="active-thread">
      <div className="cmd-thread-card" id="focused-thread-card">
        <div className="cmd-page-content wide-page">
          <div className="cmd-page-section" id="cmd-acc-list" role="tabpanel">
            {tab === 'Services' ? <AccountList /> : tab === 'Data' ? <DataPanel /> : <ConfigPanel />}
          </div>
        </div>
      </div>
    </div>
  )
}
