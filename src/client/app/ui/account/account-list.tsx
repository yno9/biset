// What sits under the identity card on the account page: the mediator and a notice when the DIDComm key needs
// a Wallet approval (the Services tab), and the keys: this identity's devices, and its PGP key (the Keys tab).
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useStore } from '../../react/store.ts'
import { didToHttpsUrl } from '../../../../protocol/webvh/identifier.ts'
import { resolve } from '../../../../protocol/webvh/resolver.ts'
import { requestText } from './text-card-dialog.tsx'
import { PgpKeyRow } from './pgp-card.tsx'
import { accountConfig, type AccountPageConfig } from './state.ts'

type Wallet = NonNullable<AccountPageConfig['wallet']>
type DidComm = NonNullable<Wallet['didComm']>
type Device = NonNullable<NonNullable<AccountPageConfig['vault']>['devices']>[number]

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

function coordinatorHost(url: string): string {
  try { return new URL(url).host } catch { return url }
}

export function AccountList() {
  const config = useStore(accountConfig)
  const wallet = config?.wallet
  if (!config || !wallet) return null
  const showMessage = (text: string) => config.showMessage?.(text)
  return (
    <>
      {config.did ? <IdentityHostCard did={config.did} showMessage={showMessage} {...(wallet.reconnectRequired && wallet.onReconnect ? { onReconnect: () => { void wallet.onReconnect?.().catch(error => showMessage(errorText(error))) } } : {})} /> : null}
      {wallet.didComm ? <MediatorCard config={config} wallet={wallet} didComm={wallet.didComm} showMessage={showMessage} /> : null}
      {config.rotationKey ? <DidCommKeyNotice rotationKey={config.rotationKey} showMessage={showMessage} /> : null}
    </>
  )
}

/** Where the identity lives: the wallet that hosts the DID and approves changes to it. The dot is green when the
 * DID resolves (its `/.well-known/did.jsonl` is there and verifies), orange while that is being looked up, red
 * when it does not. When the wallet's capability has lapsed a Reconnect button
 * is here as well. The host is a link to the wallet itself (the origin
 * the identity's keys are stored under; app.did.md is another origin and does not have them); the document icon
 * on the right opens the DID's own log, `/.well-known/did.jsonl`, in a new tab. */
type Resolution = 'checking' | 'ok' | 'error'
/** What the last look at each DID found. The card is built again each time its tab is shown; it starts from this
 * and does not look again, so switching tabs never turns the dot orange. A new DID (an alias change), or a page
 * load, looks anew. */
const resolutions = new Map<string, Resolution>()

/** The SCID cut to `chars` characters, an ellipsis the last of them: a whole number of characters (the font is monospace), so no part
 * of a character cell is left empty between the ellipsis and what follows. */
export function ellipsizeScid(scid: string, chars: number): string {
  return chars >= scid.length ? scid : `${scid.slice(0, Math.max(1, chars - 1))}…`
}

/** The SCID on one line: when the card is narrow it gives way (ellipsis). CSS
 * cannot cut a line at a whole character (the rest of a cell shows as a gap before the ellipsis's neighbour), so the width the SCID may
 * have is measured, in characters, from the room the card leaves. */
function DidText({ did }: { did: string }) {
  const parts = did.split(':')
  const scid = useRef<HTMLSpanElement>(null)
  const [chars, setChars] = useState(Infinity)
  useLayoutEffect(() => {
    const element = scid.current
    const text = element?.parentElement, row = text?.parentElement, column = row?.parentElement
    if (!element || !text || !row || !column) return
    const measure = () => {
      if (!column.clientWidth) { setChars(Infinity); return } // no layout (a test): the whole SCID
      const context = document.createElement('canvas').getContext('2d')
      if (!context) return
      context.font = getComputedStyle(element).font
      const cell = context.measureText('0').width
      const around = row.getBoundingClientRect().width - text.getBoundingClientRect().width // the icon, the gap, the padding
      // anything else on the line beside the SCID, by its own width (`text` itself may be narrower than what is in it)
      const fixed = (element.previousElementSibling?.getBoundingClientRect().width ?? 0) + (element.nextElementSibling?.getBoundingClientRect().width ?? 0)
      setChars(cell ? Math.floor((column.clientWidth - around - fixed - 1) / cell) : Infinity)
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(column)
    return () => observer.disconnect()
  }, [did])
  // Only the SCID is shown (what the DID's `did:webvh:` and `:alias.did.md` leave out is in the tooltip, and is what a click copies);
  // a DID that is not a did:webvh is shown as it is.
  return <span className="acc-did-scid" ref={scid}>{parts.length < 4 ? did : ellipsizeScid(parts[2]!, chars)}</span>
}

function IdentityHostCard({ did, showMessage, onReconnect }: { did: string; showMessage: (text: string) => void; onReconnect?: () => void }) {
  const [resolved, setResolved] = useState<Resolution>(() => resolutions.get(did) ?? 'checking')
  useEffect(() => {
    const known = resolutions.get(did)
    if (known && known !== 'checking') { setResolved(known); return }
    let current = true
    setResolved('checking')
    const done = (result: Resolution) => { resolutions.set(did, result); if (current) setResolved(result) }
    resolve(did).then(found => done(found ? 'ok' : 'error')).catch(() => done('error'))
    return () => { current = false }
  }, [did])
  const logUrl = (() => { try { return didToHttpsUrl(did) } catch { return undefined } })()
  // The host that has the DID's log (`did.jsonl`): the one the DID names.
  const host = (() => { try { return logUrl ? new URL(logUrl).host : undefined } catch { return undefined } })()
  const dotColor = resolved === 'ok' ? '#34c759' : resolved === 'error' ? '#ff3b30' : '#ff9f0a'
  // Both lines of the first row and the buttons on its right are one line high, so the buttons stay on the first line when the DID is the second.
  const LINE = 26
  return (
    <div className="acc-card-wrap" id="cmd-acc-identity-host-card">
      <div className="cmd-page-row" style={{ gap: 12, alignItems: 'flex-start', padding: '10px 12px' }}>
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minHeight: LINE }}>
            <span role="status" aria-label={resolved === 'ok' ? 'DID resolves' : resolved === 'error' ? 'DID does not resolve' : 'Resolving the DID'} data-state={resolved}
              style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0, background: dotColor }} />
            <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.04em', color: 'var(--accent2, #888)', flexShrink: 0 }}>Identity host</span>
            <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>:</span>
            {host ? <a href={`https://${host}`} target="_blank" rel="noopener noreferrer" data-tip={`Open ${host}`}
              style={{ fontSize: 14.5, fontWeight: 600, color: 'inherit', textDecoration: 'none', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{host}</a> : null}
          </div>
          {/* Clicking the DID text copies it. */}
          <div id="cmd-acc-identity-did-row"
            onClick={event => { event.stopPropagation(); navigator.clipboard?.writeText(did).then(() => showMessage('DID copied')).catch(() => {}) }}>
            <svg id="cmd-acc-identity-copy-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>
            <span id="cmd-acc-identity-did" data-tip={did}><DidText did={did} /></span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0, minHeight: LINE }}>
          {onReconnect ? <button type="button" onClick={onReconnect}
            style={{ padding: '3px 10px', border: '1px solid #ff9f0a', borderRadius: 8, background: 'none', color: '#ff9f0a', font: 'inherit', fontSize: 13, cursor: 'pointer' }}>Reconnect</button> : null}
          {logUrl ? <a href={logUrl} target="_blank" rel="noopener noreferrer" aria-label="Open the DID log" data-tip="Open the DID log (did.jsonl)"
            className="acc-icon-btn">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" /><path d="M14 3v5h5" /><path d="M9 13h6" /><path d="M9 17h6" /></svg>
          </a> : null}
        </div>
      </div>
    </div>
  )
}

function MediatorCard({ config, wallet, didComm, showMessage }: { config: AccountPageConfig; wallet: Wallet; didComm: DidComm; showMessage: (text: string) => void }) {
  const loggedOut = didComm.loggedOut === true
  const report = (error: unknown) => showMessage(errorText(error))

  // The same URL republishes the endpoint as configured now; no change of URL needed.
  const editServer = () => {
    void requestText({ title: 'DIDComm mediator', value: didComm.mediatorUrl, placeholder: 'https://', hint: 'The address of the mediator your messages arrive through.' })
      .then(url => { if (url?.trim()) return wallet.onEditMediator?.(url.trim()) }).catch(report)
  }
  const enableTor = () => {
    void requestText({ title: 'Onion address', value: didComm.onionUrl ?? '', placeholder: 'http://….onion', hint: 'The mediator\'s Tor address, published beside its usual one.', button: 'Enable Tor' })
      .then(onion => { if (onion?.trim()) return wallet.onEnableTor?.(onion.trim()) }).catch(report)
  }

  const status = didComm.error ? `Needs attention: ${didComm.error}` : loggedOut ? 'Logged out' : ''
  const dotColor = didComm.error ? '#ff3b30' : loggedOut ? '#8e8e93' : didComm.connecting ? '#ff9f0a' : '#34c759'

  return (
    <div className="acc-card-wrap" id="cmd-acc-mediator-card">
      <div className="cmd-page-row" style={{ gap: 12, alignItems: 'center', padding: '10px 12px' }}>
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0, background: dotColor }} />
            <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.04em', color: 'var(--accent2, #888)', flexShrink: 0 }}>Mediator</span>
            <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>:</span>
            <span style={{ fontSize: 14.5, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{coordinatorHost(didComm.mediatorUrl)}</span>
            {/* The dot says registered or connecting; the line only speaks for what a colour cannot. */}
            {status ? <span style={{ fontSize: 12, flexShrink: 1, minWidth: 0, color: didComm.error ? '#ff3b30' : 'var(--text-dim)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{status}</span> : null}
          </div>
        </div>
        {/* Enable Tor, then edit the server (the pencil of the alias change): an icon each, on the right, each opening a card. Logged out, the one thing to do is log in. */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 2, flexShrink: 0 }}>
          {loggedOut ? (
            wallet.onEnableMessaging ? <button type="button" className="acc-text-btn" onClick={() => { void wallet.onEnableMessaging?.().catch(report) }}>Log in</button> : null
          ) : (
            <>
              {wallet.onEnableTor ? (
                <button type="button" className="acc-icon-btn" aria-label="Enable Tor" data-tip="Enable Tor" onClick={enableTor}>
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 2.5c0 2-1 3.2-2.2 4.4C6.2 8.6 4 11.6 4 15a8 7.5 0 0 0 16 0c0-3.4-2.2-6.4-5.8-8.1C13 5.7 12 4.5 12 2.5Z" /><path d="M12 7c-2 2-3 5-3 8s1 5 3 6c2-1 3-3 3-6s-1-6-3-8Z" /></svg>
                </button>
              ) : null}
              {wallet.onEditMediator ? (
                <button type="button" className="acc-icon-btn" aria-label="Edit server" data-tip="Edit server" onClick={editServer}>
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z" /></svg>
                </button>
              ) : null}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

/** The Keys tab: the devices that hold this identity's DIDComm key, and its PGP key. */
export function KeysPanel() {
  const config = useStore(accountConfig)
  if (!config) return null
  const showMessage = (text: string) => config.showMessage?.(text)
  return (
    <div id="cmd-acc-keys">
      <DeviceKeyCard config={config} showMessage={showMessage} />
      <div className="acc-card-wrap acc-key-card" id="cmd-acc-pgp-key-card">
        <div className="acc-storage-header"><span className="acc-storage-title">PGP Key</span></div>
        {config.pgp ? <PgpKeyRow config={config.pgp} showMessage={showMessage} /> : <div className="acc-device-empty">No key available</div>}
      </div>
    </div>
  )
}

function DeviceKeyCard({ config, showMessage }: { config: AccountPageConfig; showMessage: (text: string) => void }) {
  const [removing, setRemoving] = useState(false)
  const [previewRemoval, setPreviewRemoval] = useState(false)
  const report = (error: unknown) => showMessage(errorText(error))
  const removeOtherDevices = () => {
    if (removing || !config.onRemoveOtherDevices) return
    if (!confirm('Remove all other devices? They will need to sign in again. Content they already received cannot be revoked.')) return
    setRemoving(true)
    config.onRemoveOtherDevices()
      .then(() => showMessage('Other devices removed'))
      .catch(error => { setRemoving(false); report(error) })
  }

  const roster = [...(config.vault?.devices ?? [])].sort((a, b) => Number(b.current) - Number(a.current))
  return (
    <div className="acc-card-wrap acc-key-card" id="cmd-acc-device-key-card">
      <div className="acc-storage-header"><span className="acc-storage-title">Device Key</span></div>
      <div className={`acc-device-list${previewRemoval ? ' remove-preview' : ''}`} onPointerLeave={() => setPreviewRemoval(false)}
        onPointerOver={event => setPreviewRemoval(event.target instanceof Element && Boolean(event.target.closest('.acc-device-removable')))}>
        {roster.length ? roster.map(device => (
          <DeviceRow key={device.deviceId} device={device} removable={!device.current && Boolean(config.onRemoveOtherDevices)} disabled={removing} onRemove={removeOtherDevices} />
        )) : <div className="acc-device-empty">No devices available</div>}
      </div>
    </div>
  )
}

function DeviceRow({ device, removable, disabled, onRemove }: { device: Device; removable: boolean; disabled: boolean; onRemove: () => void }) {
  const fragment = device.deviceId.includes('#') ? device.deviceId.slice(device.deviceId.indexOf('#')) : device.deviceId
  const content = (
    <>
      <span className="acc-device-label" title={device.deviceId}>{fragment.length > 18 ? `${fragment.slice(0, 10)}…` : fragment}</span>
      {device.lastActivity ? <span className="acc-device-activity">{new Date(device.lastActivity).toLocaleString()}</span> : null}
      {device.current ? <span className="acc-device-current">this device</span> : removable ? (
        <span className="acc-device-trash" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18" /><path d="M8 6V4h8v2" /><path d="m19 6-1 14H6L5 6" /><path d="M10 11v5" /><path d="M14 11v5" /></svg>
        </span>
      ) : null}
    </>
  )
  return removable
    ? <button type="button" className="acc-device-row acc-device-removable" disabled={disabled} aria-label={`Remove other devices, including ${device.deviceId}`} onClick={onRemove}>{content}</button>
    : <div className="acc-device-row">{content}</div>
}

/** Why, in the user's words (the states are generation-seed-bootstrap.ts's). */
const DIDCOMM_KEY_REASON = {
  unpublished: 'Your account has no DIDComm key yet. It lets your devices keep a conversation private.',
  lost: 'None of your devices has it any more.',
  stale: 'A device you removed may still have it.',
} as const

/** The system message card for the DIDComm key (generation-seed-bootstrap.ts): "Your DIDComm key
 * needs to be renewed", the link starting the one Wallet approval that publishes a fresh one. It
 * stays until the key is in order. */
function DidCommKeyNotice({ rotationKey, showMessage }: { rotationKey: NonNullable<AccountPageConfig['rotationKey']>; showMessage: (text: string) => void }) {
  const [renewing, setRenewing] = useState(false)
  return (
    <div className="acc-notice" id="cmd-acc-didcomm-key-notice" role="status">
      <span className="acc-notice-dot" />
      <div className="acc-notice-body">
        <div className="acc-notice-title">
          Your DIDComm key needs to be{' '}
          <a className="acc-notice-link" href="#renew-didcomm-key" aria-disabled={renewing ? 'true' : undefined}
            onClick={event => {
              event.preventDefault()
              if (renewing) return
              setRenewing(true)
              rotationKey.onRenew().catch(error => { setRenewing(false); showMessage(errorText(error)) })
            }}>renewed</a>.
        </div>
        <div className="acc-notice-detail">{DIDCOMM_KEY_REASON[rotationKey.state]}</div>
      </div>
    </div>
  )
}
